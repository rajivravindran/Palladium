package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	policy "river3.local/policy"
)

// OpenShell drives NVIDIA OpenShell sandboxes through its CLI (`openshell sandbox ...`).
// It is opt-in and has NOT been exercised against a real OpenShell gateway yet; the
// command shapes follow the public docs (stop / start / delete / list) and are isolated
// in Runner so a test or a later version can swap them.
//
// Mapping. River3 identifies a workload by a full 64-hex container id (registry rule),
// OpenShell by a sandbox name. The adapter takes a mapping file:
//
//	{"<64-hex container id>": {"sandbox": "dev", "generation": "generation-1"}}
//
// `generation` is echoed back on Inspect because the CLI exposes no restart marker
// (`sandbox list` prints NAME / STATUS / AGE, and AGE is relative, so it cannot serve as
// one). This is the one adapter whose generation is configuration, not an observation:
// a sandbox deleted and recreated under the same name out of band is NOT detected by
// this adapter, where Podman and Docker would see a new StartedAt and refuse to act.
// Inspect says so in Info.Note, which the controller journals with the observed state,
// so the weaker evidence is visible in every incident and audit row rather than looking
// like a verified generation. Keep the registry's generation equal to the mapping's.
// There is no live test for this adapter (no OpenShell gateway here).
//
// Semantics. OpenShell has no pause: Pause = `sandbox stop` (the workspace, policies and
// record stay; the compute stops, so the agent cannot act), Resume = `sandbox start`,
// Terminate = `sandbox delete`. The controller still verifies by Inspect, never by exit code.
type OpenShell struct {
	bin     string
	run     Runner
	timeout time.Duration
	boxes   map[string]openShellBox
}

type openShellBox struct {
	Sandbox    string `json:"sandbox"`
	Generation string `json:"generation"`
}

// Runner executes the CLI. Arguments are passed as a vector; nothing becomes a shell string.
type Runner func(ctx context.Context, bin string, args ...string) ([]byte, error)

var sandboxName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func NewOpenShell(bin, mappingPath string) (*OpenShell, error) {
	if bin == "" {
		bin = "openshell"
	}
	data, err := os.ReadFile(mappingPath)
	if err != nil {
		return nil, fmt.Errorf("openshell: mapping: %w", err)
	}
	var boxes map[string]openShellBox
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&boxes); err != nil {
		return nil, fmt.Errorf("openshell: mapping %s: %w", mappingPath, err)
	}
	seen := map[string]string{}
	for cid, b := range boxes {
		if err := checkID(cid); err != nil {
			return nil, fmt.Errorf("openshell: mapping key %q must be a full 64-hex container id", short(cid))
		}
		if !sandboxName.MatchString(b.Sandbox) {
			return nil, fmt.Errorf("openshell: mapping %s: invalid sandbox name %q", short(cid), b.Sandbox)
		}
		if b.Generation == "" {
			return nil, fmt.Errorf("openshell: mapping %s: generation is required", short(cid))
		}
		if other, dup := seen[b.Sandbox]; dup {
			return nil, fmt.Errorf("openshell: sandbox %q mapped twice (%s, %s)", b.Sandbox, short(other), short(cid))
		}
		seen[b.Sandbox] = cid
	}
	return &OpenShell{bin: bin, run: execRunner, timeout: 20 * time.Second, boxes: boxes}, nil
}

// WithRunner swaps the CLI executor (tests).
func (o *OpenShell) WithRunner(r Runner) *OpenShell { o.run = r; return o }

func execRunner(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), errors.New(msg)
	}
	return out.Bytes(), nil
}

func (o *OpenShell) Name() string             { return "openshell" }
func (o *OpenShell) Actions() []policy.Action { return []policy.Action{policy.Pause} }

func (o *OpenShell) box(id string) (openShellBox, error) {
	if err := checkID(id); err != nil {
		return openShellBox{}, errors.New("openshell: refusing non-full container id")
	}
	b, ok := o.boxes[id]
	if !ok {
		return openShellBox{}, fmt.Errorf("openshell: container %s is not mapped to a sandbox", short(id))
	}
	return b, nil
}

func (o *OpenShell) cli(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	return o.run(ctx, o.bin, args...)
}

// Inspect lists sandboxes and reads the row for this one. `list` is used rather than a
// per-sandbox command because its NAME / STATUS table is the shape the docs show.
func (o *OpenShell) Inspect(ctx context.Context, id string) (Info, error) {
	b, err := o.box(id)
	if err != nil {
		return Info{}, err
	}
	out, err := o.cli(ctx, "sandbox", "list", "--filter", b.Sandbox)
	if err != nil {
		return Info{}, fmt.Errorf("openshell list: %w", err)
	}
	status, found := parseSandboxList(out, b.Sandbox)
	if !found {
		return Info{ContainerID: id, Generation: b.Generation, Status: Missing, Note: GenerationEchoNote}, nil
	}
	return Info{ContainerID: id, Generation: b.Generation, Status: mapOpenShellStatus(status), Note: GenerationEchoNote}, nil
}

// GenerationEchoNote marks an Info whose generation came from the mapping file rather
// than from the runtime (see the OpenShell type comment).
const GenerationEchoNote = "generation echoed from the sandbox mapping, not observed from the runtime; a recreated sandbox is not detected"

// parseSandboxList reads `openshell sandbox list` output: a header line with NAME and
// STATUS columns, then one row per sandbox. Returns the status for name.
func parseSandboxList(out []byte, name string) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	nameCol, statusCol := -1, -1
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) == 0 {
			continue
		}
		if nameCol < 0 {
			for i, f := range fields {
				switch strings.ToUpper(f) {
				case "NAME":
					nameCol = i
				case "STATUS", "PHASE", "STATE":
					statusCol = i
				}
			}
			if nameCol < 0 || statusCol < 0 {
				nameCol = -1 // not the header yet
			}
			continue
		}
		if len(fields) > nameCol && len(fields) > statusCol && fields[nameCol] == name {
			return fields[statusCol], true
		}
	}
	return "", false
}

func mapOpenShellStatus(s string) Status {
	switch strings.ToLower(s) {
	case "running", "ready":
		return Running
	case "stopped", "suspended":
		return Paused // compute stopped, record kept: River3's "paused"
	case "deleted", "terminated", "deleting", "failed":
		return Exited
	case "starting", "stopping", "pending", "creating":
		return Unknown // in transition; the controller records UNKNOWN rather than guess
	}
	return Unknown
}

func (o *OpenShell) mutate(ctx context.Context, id, verb string) error {
	b, err := o.box(id)
	if err != nil {
		return err
	}
	args := []string{"sandbox", verb, b.Sandbox}
	if verb == "delete" {
		args = append(args, "--yes")
	}
	if _, err := o.cli(ctx, args...); err != nil {
		return fmt.Errorf("openshell %s %s: %w", verb, b.Sandbox, err)
	}
	return nil
}

func (o *OpenShell) Pause(ctx context.Context, id string) error  { return o.mutate(ctx, id, "stop") }
func (o *OpenShell) Resume(ctx context.Context, id string) error { return o.mutate(ctx, id, "start") }
func (o *OpenShell) Terminate(ctx context.Context, id string) error {
	return o.mutate(ctx, id, "delete")
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
