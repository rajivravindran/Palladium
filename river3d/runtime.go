package main

// Container runtimes: resolve a container id to its init PID, and discover
// containers that opted in with labels (contract §4.1 / §4.3).
//
// Docker's Engine API and Podman's libpod API are shaped alike for the two calls
// used here (list with a label filter, inspect for State.Pid), so one client
// serves both behind a path prefix. Labels are read from the runtime's own
// database, not from inside the container: a workload cannot relabel itself.
// What a label CAN do is claim an asset id or profile; that is the operator's
// trust decision when they allow label enrollment, and the -enroll file always
// wins a conflict so an explicit enrollment cannot be hijacked by a label.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ContainerRuntime is what enrollment needs from a runtime.
type ContainerRuntime interface {
	RuntimeResolver
	// List returns the running containers carrying river3.enroll=true.
	List(ctx context.Context) ([]containerSummary, error)
	// ListLabelled returns the running containers carrying the given label (any value).
	ListLabelled(ctx context.Context, label string) ([]containerSummary, error)
}

type containerSummary struct {
	ID     string
	Names  []string
	Labels map[string]string
	State  string
}

// runtimeClient talks to docker or podman over a unix socket.
//
// Two API flavours are spoken. `-runtime podman` uses libpod's own routes
// (`/v4.0.0/libpod/...`); `-discover docker|podman` uses the Docker-compatible
// Engine API, which docker serves unprefixed and podman serves under a version
// prefix (`/v4.0.0/...`) as well as unprefixed. For the compat client the prefix is
// not assumed: it is probed once with `/_ping` and remembered.
type runtimeClient struct {
	kind   string // "docker" | "podman"
	socket string
	client *http.Client // 10 s timeout: list and inspect
	stream *http.Client // no timeout: /events (bounded by ctx instead)

	mu         sync.Mutex
	prefix     string   // "" for docker, "/v4.0.0/libpod" for podman (libpod flavour)
	candidates []string // compat flavour: prefixes still to try, in order; nil once settled
}

// compatPrefixes are the Engine-API prefixes probed by newCompatClient, most likely
// first for each runtime. Podman answers both; docker only the bare one.
var compatPrefixes = map[string][]string{
	"docker": {"", "/v1.41"},
	"podman": {"/v4.0.0", ""},
}

func newTransport(socket string) *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
}

func checkRuntimeArgs(kind, socket string) error {
	if !strings.HasPrefix(socket, "/") {
		return fmt.Errorf("%s socket must be an absolute path", kind)
	}
	if kind != "docker" && kind != "podman" {
		return fmt.Errorf("unknown runtime %q (docker | podman)", kind)
	}
	return nil
}

// newRuntimeClient is the -runtime client: libpod routes for podman, Engine API for docker.
func newRuntimeClient(kind, socket string) (*runtimeClient, error) {
	if err := checkRuntimeArgs(kind, socket); err != nil {
		return nil, err
	}
	prefix := ""
	if kind == "podman" {
		prefix = "/v4.0.0/libpod"
	}
	return &runtimeClient{kind: kind, socket: socket, prefix: prefix,
		client: &http.Client{Transport: newTransport(socket), Timeout: 10 * time.Second},
		stream: &http.Client{Transport: newTransport(socket)}}, nil
}

// newCompatClient is the -discover client: the Docker-compatible Engine API on either
// runtime, with the path prefix probed on first use.
func newCompatClient(kind, socket string) (*runtimeClient, error) {
	if err := checkRuntimeArgs(kind, socket); err != nil {
		return nil, err
	}
	return &runtimeClient{kind: kind, socket: socket, candidates: append([]string{}, compatPrefixes[kind]...),
		client: &http.Client{Transport: newTransport(socket), Timeout: 10 * time.Second},
		stream: &http.Client{Transport: newTransport(socket)}}, nil
}

// resolvePrefix settles the compat prefix with GET <prefix>/_ping. A failure leaves
// the candidates in place so the next call probes again (the daemon may not be up yet).
func (r *runtimeClient) resolvePrefix(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.candidates == nil {
		return r.prefix, nil
	}
	var lastErr error
	for _, p := range r.candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+r.kind+p+"/_ping", nil)
		if err != nil {
			return "", err
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("%s: %w", r.kind, err) // socket-level: no point trying other prefixes
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			r.prefix, r.candidates = p, nil
			return p, nil
		}
		lastErr = fmt.Errorf("%s: GET %s/_ping: HTTP %d", r.kind, p, resp.StatusCode)
	}
	return "", lastErr
}

// newRequest builds a GET for the API path p (no prefix), resolving the prefix first.
func (r *runtimeClient) newRequest(ctx context.Context, p string) (*http.Request, error) {
	prefix, err := r.resolvePrefix(ctx)
	if err != nil {
		return nil, err
	}
	return http.NewRequestWithContext(ctx, http.MethodGet, "http://"+r.kind+prefix+p, nil)
}

func (r *runtimeClient) get(ctx context.Context, p string, out any) (int, error) {
	req, err := r.newRequest(ctx, p)
	if err != nil {
		return 0, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%s: HTTP %d", r.kind, resp.StatusCode)
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// PID implements RuntimeResolver. Only the full id is accepted, and the runtime
// must echo it back: a prefix match inside the runtime could land on another
// container.
func (r *runtimeClient) PID(ctx context.Context, id string) (uint32, error) {
	if !fullCIDRe.MatchString(id) {
		return 0, errors.New("refusing non-full container id")
	}
	var out struct {
		ID    string `json:"Id"`
		State struct {
			Status string `json:"Status"`
			Pid    uint32 `json:"Pid"`
		} `json:"State"`
	}
	status, err := r.get(ctx, "/containers/"+id+"/json", &out)
	if status == http.StatusNotFound {
		return 0, errNotRunning
	}
	if err != nil {
		return 0, fmt.Errorf("inspect: %w", err)
	}
	if out.ID != id {
		return 0, errors.New("runtime returned a different container id")
	}
	if out.State.Status != "running" && out.State.Status != "paused" || out.State.Pid == 0 {
		return 0, errNotRunning
	}
	return out.State.Pid, nil
}

// List implements ContainerRuntime. Both APIs take the same JSON filter and
// return running containers only by default; State is checked anyway.
func (r *runtimeClient) List(ctx context.Context) ([]containerSummary, error) {
	return r.list(ctx, labelEnroll+"=true")
}

// ListLabelled implements ContainerRuntime: running containers carrying `label`
// with any value (the -discover path, keyed on river3.workload).
func (r *runtimeClient) ListLabelled(ctx context.Context, label string) ([]containerSummary, error) {
	return r.list(ctx, label)
}

func (r *runtimeClient) list(ctx context.Context, labelFilter string) ([]containerSummary, error) {
	filters := url.QueryEscape(`{"label":["` + labelFilter + `"]}`)
	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Labels map[string]string `json:"Labels"`
		State  string            `json:"State"`
	}
	if _, err := r.get(ctx, "/containers/json?filters="+filters, &raw); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	out := make([]containerSummary, 0, len(raw))
	for _, c := range raw {
		if c.State != "running" || !fullCIDRe.MatchString(c.ID) {
			continue
		}
		out = append(out, containerSummary{ID: c.ID, Names: c.Names, Labels: c.Labels, State: c.State})
	}
	return out, nil
}

// containerEventFilter selects the lifecycle events that can change the set of
// running containers (or their PIDs); everything else on the bus is noise here.
const containerEventFilter = `{"type":["container"],"event":["start","die","stop","pause","unpause"]}`

// Events follows GET /events (a stream of JSON objects, one per event) and calls
// onEvent for each, until ctx ends. The payload is not interpreted: any container
// lifecycle event means "re-list now". A closed or failed stream is reopened with
// backoff (1 s doubling to 30 s); the caller never waits on this.
func (r *runtimeClient) Events(ctx context.Context, onEvent func(), log func(string, ...any)) {
	delay := time.Second
	for ctx.Err() == nil {
		err := r.streamEvents(ctx, onEvent)
		if ctx.Err() != nil {
			return
		}
		if err == nil || errors.Is(err, io.EOF) {
			// A clean close (daemon restart, test server) is normal: reconnect quickly.
			delay = time.Second
		} else {
			log("discover: %s events: %v (retrying in %s)", r.kind, err, delay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

func (r *runtimeClient) streamEvents(ctx context.Context, onEvent func()) error {
	req, err := r.newRequest(ctx, "/events?filters="+url.QueryEscape(containerEventFilter))
	if err != nil {
		return err
	}
	resp, err := r.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// One object at a time; a bound on the whole stream would end a healthy
	// connection, so each event is bounded instead (the decoder buffers one value).
	dec := json.NewDecoder(resp.Body)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if len(raw) > 64<<10 {
			return errors.New("event larger than 64 KiB")
		}
		onEvent()
	}
}

// ---------------------------------------------------------------------------
// labels → enrollments
// ---------------------------------------------------------------------------

const (
	labelEnroll  = "river3.enroll"
	labelAssetID = "river3.asset_id"
	labelProfile = "river3.profile"
	labelKind    = "river3.kind"
	labelName    = "river3.name"
	labelTeam    = "river3.team"
	// river3.dedicated and river3.actions are the controller's business (§4.1);
	// the sensor ignores them.
)

// enrollmentFromLabels validates the contract's labels on one container. The
// same rules as the -enroll file apply, so a label can never produce an
// enrollment the file could not.
func enrollmentFromLabels(c containerSummary) (Enrollment, error) {
	l := c.Labels
	if l[labelEnroll] != "true" {
		return Enrollment{}, errors.New("river3.enroll is not \"true\"")
	}
	en := Enrollment{
		AssetID: l[labelAssetID], Profile: l[labelProfile], Kind: l[labelKind], Name: l[labelName],
		Team: l[labelTeam], ContainerID: c.ID,
	}
	if !identRe.MatchString(en.AssetID) {
		return Enrollment{}, errors.New("river3.asset_id missing or not an identifier")
	}
	if en.Profile == "" {
		return Enrollment{}, errors.New("river3.profile missing")
	}
	if en.Kind != "ai_worker" && en.Kind != "shared_service" {
		return Enrollment{}, errors.New("river3.kind must be ai_worker or shared_service")
	}
	if len(en.Team) > 64 {
		return Enrollment{}, errors.New("river3.team longer than 64")
	}
	if en.Name == "" {
		for _, n := range c.Names {
			if n = strings.TrimPrefix(n, "/"); n != "" {
				en.Name = n
				break
			}
		}
	}
	if en.Name == "" {
		en.Name = en.AssetID
	}
	return en, nil
}

// discoverEnrollments lists labelled containers and turns them into enrollments.
// A container with bad labels is reported and skipped; the others still enrol.
func discoverEnrollments(ctx context.Context, rt ContainerRuntime) ([]Enrollment, []string, error) {
	list, err := rt.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	var out []Enrollment
	var problems []string
	for _, c := range list {
		en, err := enrollmentFromLabels(c)
		if err != nil {
			problems = append(problems, fmt.Sprintf("container %s: %v", c.ID[:12], err))
			continue
		}
		out = append(out, en)
	}
	return out, problems, nil
}

// mergeEnrollments combines the -enroll file with discovered enrollments. The
// file wins every conflict (same asset_id or same container_id); among discovered
// entries the first (by container id) keeps a duplicated asset_id. The result is
// capped at maxEnrolled: discovered entries beyond it are dropped, never file ones.
// Conflicts and the cap are returned for logging.
func mergeEnrollments(file, discovered []Enrollment) ([]Enrollment, []string) {
	out := append([]Enrollment{}, file...)
	byAsset := map[string]bool{}
	byCID := map[string]bool{}
	for _, e := range file {
		byAsset[e.AssetID] = true
		if e.ContainerID != "" {
			byCID[e.ContainerID] = true
		}
	}
	var conflicts []string
	dropped := 0
	for _, e := range discovered {
		switch {
		case byAsset[e.AssetID]:
			conflicts = append(conflicts, fmt.Sprintf("asset %s: label enrollment ignored (already enrolled)", e.AssetID))
			continue
		case e.ContainerID != "" && byCID[e.ContainerID]:
			conflicts = append(conflicts, fmt.Sprintf("container %s: label enrollment ignored (already enrolled)", e.ContainerID[:12]))
			continue
		case len(out) >= maxEnrolled:
			dropped++
			continue
		}
		byAsset[e.AssetID] = true
		if e.ContainerID != "" {
			byCID[e.ContainerID] = true
		}
		out = append(out, e)
	}
	if dropped > 0 {
		conflicts = append(conflicts, fmt.Sprintf("%d discovered enrollment(s) dropped: at most %d enrollments in total", dropped, maxEnrolled))
	}
	return out, conflicts
}
