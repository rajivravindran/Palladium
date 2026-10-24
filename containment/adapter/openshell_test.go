package adapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const osCID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func writeMapping(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sandboxes.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type fakeCLI struct {
	calls  [][]string
	status string // what `sandbox list` reports; "" = not listed
	fail   error
}

func (f *fakeCLI) run(_ context.Context, bin string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{bin}, args...))
	if f.fail != nil {
		return nil, f.fail
	}
	if len(args) >= 2 && args[1] == "list" {
		out := "NAME        STATUS    AGE\n"
		if f.status != "" {
			out += "other       running   00:10:00\n"
			out += "agent-dev   " + f.status + "   00:00:42\n"
		}
		return []byte(out), nil
	}
	switch args[1] {
	case "stop":
		f.status = "stopped"
	case "start":
		f.status = "running"
	case "delete":
		f.status = ""
	}
	return nil, nil
}

func newOS(t *testing.T) (*OpenShell, *fakeCLI) {
	t.Helper()
	a, err := NewOpenShell("openshell", writeMapping(t, `{"`+osCID+`": {"sandbox": "agent-dev", "generation": "gen-1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCLI{status: "running"}
	return a.WithRunner(f.run), f
}

func TestOpenShellMappingValidation(t *testing.T) {
	for name, body := range map[string]string{
		"short id":    `{"abc": {"sandbox": "x", "generation": "g"}}`,
		"bad name":    `{"` + osCID + `": {"sandbox": "Agent_Dev", "generation": "g"}}`,
		"no gen":      `{"` + osCID + `": {"sandbox": "a"}}`,
		"unknown key": `{"` + osCID + `": {"sandbox": "a", "generation": "g", "extra": 1}}`,
		"dup sandbox": `{"` + osCID + `": {"sandbox": "a", "generation": "g"}, "` + strings.Repeat("d", 64) + `": {"sandbox": "a", "generation": "g"}}`,
	} {
		if _, err := NewOpenShell("", writeMapping(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestOpenShellLifecycle(t *testing.T) {
	a, f := newOS(t)
	ctx := context.Background()
	info, err := a.Inspect(ctx, osCID)
	if err != nil || info.Status != Running || info.Generation != "gen-1" || info.ContainerID != osCID {
		t.Fatalf("inspect: %+v %v", info, err)
	}
	// The generation is the mapping's, not the runtime's: every Inspect says so, so the
	// controller journals the weaker evidence next to the observed state.
	if info.Note != GenerationEchoNote || !strings.Contains(info.Note, "not observed from the runtime") {
		t.Fatalf("generation echo not flagged: %q", info.Note)
	}
	if err := a.Pause(ctx, osCID); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls[len(f.calls)-1], " "); got != "openshell sandbox stop agent-dev" {
		t.Fatalf("pause ran %q", got)
	}
	if info, _ = a.Inspect(ctx, osCID); info.Status != Paused {
		t.Fatalf("after stop: %s", info.Status)
	}
	if err := a.Resume(ctx, osCID); err != nil {
		t.Fatal(err)
	}
	if info, _ = a.Inspect(ctx, osCID); info.Status != Running {
		t.Fatalf("after start: %s", info.Status)
	}
	if err := a.Terminate(ctx, osCID); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls[len(f.calls)-1], " "); got != "openshell sandbox delete agent-dev --yes" {
		t.Fatalf("terminate ran %q", got)
	}
	if info, _ = a.Inspect(ctx, osCID); info.Status != Missing {
		t.Fatalf("after delete: %s", info.Status)
	}
}

func TestOpenShellRefusesUnmappedAndReportsCLIErrors(t *testing.T) {
	a, f := newOS(t)
	ctx := context.Background()
	if err := a.Pause(ctx, strings.Repeat("e", 64)); err == nil || !strings.Contains(err.Error(), "not mapped") {
		t.Fatalf("unmapped: %v", err)
	}
	if err := a.Pause(ctx, "agent-dev"); err == nil {
		t.Fatal("a sandbox name must not be accepted as an id")
	}
	f.fail = errors.New("gateway unreachable")
	if _, err := a.Inspect(ctx, osCID); err == nil {
		t.Fatal("inspect must surface CLI failure, never guess")
	}
	if err := a.Pause(ctx, osCID); err == nil || !strings.Contains(err.Error(), "gateway unreachable") {
		t.Fatalf("pause: %v", err)
	}
}

func TestParseSandboxList(t *testing.T) {
	out := []byte("Fetching...\nNAME   STATUS   AGE\ndev    Ready    1h\nagent  Stopped  2m\n")
	if s, ok := parseSandboxList(out, "agent"); !ok || s != "Stopped" {
		t.Fatalf("%q %v", s, ok)
	}
	if _, ok := parseSandboxList(out, "nope"); ok {
		t.Fatal("unexpected match")
	}
	for in, want := range map[string]Status{"Ready": Running, "running": Running, "Stopped": Paused, "Starting": Unknown, "Failed": Exited, "weird": Unknown} {
		if got := mapOpenShellStatus(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}
