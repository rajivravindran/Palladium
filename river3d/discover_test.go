package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// compatEngine is a fake Docker-compatible Engine API over a unix socket. It answers
// only under the given path prefixes ("" for docker; "/v4.0.0" for a podman that is
// served only versioned), records request paths, and serves /events as one event
// followed by a close.
type compatEngine struct {
	t        *testing.T
	socket   string
	prefixes []string
	mu       sync.Mutex
	paths    []string
	list     []map[string]any
	inspect  map[string]map[string]any
	events   atomic.Int32 // /events connections served
}

func newCompatEngine(t *testing.T, prefixes ...string) *compatEngine {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "c.sock")
	if len(socket) > 100 {
		socket = filepath.Join("/tmp", filepath.Base(dir)+"c.sock")
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	e := &compatEngine{t: t, socket: socket, prefixes: prefixes, inspect: map[string]map[string]any{}}
	e.list = []map[string]any{
		{"Id": cidA, "Names": []string{"/worker-01"}, "State": "running", "Labels": map[string]string{
			labelWorkload: "worker-01", labelProfile: "diagnostic-worker", labelKind: "ai_worker"}},
		{"Id": cidB, "Names": []string{"/payments"}, "State": "running", "Labels": map[string]string{
			labelWorkload: "svc-b", labelProfile: "payment-service", labelKind: "shared_service", labelTeam: "payments", labelName: "Payments"}},
		{"Id": cidC, "Names": []string{"/bad"}, "State": "running", "Labels": map[string]string{
			labelWorkload: "has space", labelProfile: "p", labelKind: "ai_worker"}},
		{"Id": "dddddddddddd", "Names": []string{"/short"}, "State": "running", "Labels": map[string]string{labelWorkload: "short"}},
	}
	e.inspect[cidA] = map[string]any{"Id": cidA, "State": map[string]any{"Status": "running", "Pid": 2001}}
	e.inspect[cidB] = map[string]any{"Id": cidB, "State": map[string]any{"Status": "running", "Pid": 2002}}
	srv := &http.Server{Handler: http.HandlerFunc(e.serve)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return e
}

func (e *compatEngine) seen() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.paths...)
}

func (e *compatEngine) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.paths = append(e.paths, r.URL.RequestURI())
	e.mu.Unlock()
	p := ""
	matched := false
	for _, pre := range e.prefixes {
		if pre == "" {
			if !strings.HasPrefix(r.URL.Path, "/v") {
				p, matched = r.URL.Path, true
				break
			}
			continue
		}
		if strings.HasPrefix(r.URL.Path, pre+"/") {
			p, matched = strings.TrimPrefix(r.URL.Path, pre), true
			break
		}
	}
	if !matched {
		w.WriteHeader(404)
		return
	}
	switch {
	case p == "/_ping":
		_, _ = w.Write([]byte("OK"))
	case p == "/containers/json":
		if !strings.Contains(r.URL.Query().Get("filters"), `"label":["`+labelWorkload+`"]`) {
			w.WriteHeader(400)
			return
		}
		e.mu.Lock()
		list := e.list
		e.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
	case strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")
		e.mu.Lock()
		c, ok := e.inspect[id]
		e.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(c)
	case p == "/events":
		if !strings.Contains(r.URL.Query().Get("filters"), `"type":["container"]`) {
			w.WriteHeader(400)
			return
		}
		e.events.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprintf(w, `{"Type":"container","Action":"start","Actor":{"ID":%q},"time":1}`+"\n", cidA)
		// then close: the client must reconnect, not give up
	default:
		w.WriteHeader(404)
	}
}

func TestCompatDiscoveryDockerAndPodmanPrefixes(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		prefixes   []string
		wantPrefix string
	}{
		{"docker unprefixed", "docker", []string{""}, ""},
		{"podman versioned only", "podman", []string{"/v4.0.0"}, "/v4.0.0"},
		{"podman kind against an unversioned server", "podman", []string{""}, ""}, // probe falls through
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newCompatEngine(t, tc.prefixes...)
			rt, err := newCompatClient(tc.kind, eng.socket)
			if err != nil {
				t.Fatal(err)
			}
			d := newDiscoverer(rt, tc.kind)
			ctx := context.Background()
			found, problems, err := d.Discover(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(found) != 2 || found[0].AssetID != "worker-01" || found[1].AssetID != "svc-b" {
				t.Fatalf("%+v", found)
			}
			if found[0].Discovered != tc.kind || found[0].Name != "worker-01" || found[0].ContainerID != cidA || found[0].Profile != "diagnostic-worker" || found[0].Kind != "ai_worker" {
				t.Fatalf("%+v", found[0])
			}
			if found[1].Name != "Payments" || found[1].Team != "payments" || found[1].Kind != "shared_service" {
				t.Fatalf("%+v", found[1])
			}
			// The bad asset id is reported once; the short id never reaches the labels
			// (the listing drops anything that is not a full id).
			if len(problems) != 1 || !strings.Contains(problems[0], "cccccccccccc") || !strings.Contains(problems[0], labelWorkload) {
				t.Fatalf("%v", problems)
			}
			// Second listing: same problems, not reported again.
			_, problems, err = d.Discover(ctx)
			if err != nil || len(problems) != 0 {
				t.Fatalf("problems repeated: %v %v", problems, err)
			}
			// Inspect works through the same client, with the probed prefix.
			pid, err := rt.PID(ctx, cidA)
			if err != nil || pid != 2001 {
				t.Fatal(pid, err)
			}
			for _, p := range eng.seen() {
				if strings.HasSuffix(p, "/_ping") {
					continue
				}
				if !strings.HasPrefix(p, tc.wantPrefix+"/containers/") {
					t.Fatalf("unexpected path %s (want prefix %q)", p, tc.wantPrefix)
				}
			}
			// The prefix was settled once.
			pings := 0
			for _, p := range eng.seen() {
				if strings.HasSuffix(p, "/_ping") {
					pings++
				}
			}
			if pings > len(compatPrefixes[tc.kind]) {
				t.Fatalf("prefix probed %d times", pings)
			}
		})
	}
}

func TestCompatDiscoveryEventsKickAndReconnect(t *testing.T) {
	eng := newCompatEngine(t, "")
	rt, err := newCompatClient("docker", eng.socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var kicks atomic.Int32
	done := make(chan struct{})
	go func() {
		rt.Events(ctx, func() { kicks.Add(1) }, func(string, ...any) {})
		close(done)
	}()
	deadline := time.Now().Add(4 * time.Second)
	for kicks.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// One event per connection, so two kicks prove the stream was reopened after the close.
	if kicks.Load() < 2 || eng.events.Load() < 2 {
		t.Fatalf("kicks=%d connections=%d", kicks.Load(), eng.events.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Events did not return after cancel")
	}
}

func TestCompatClientSocketDownIsAnError(t *testing.T) {
	rt, err := newCompatClient("docker", "/nonexistent/river3-test.sock")
	if err != nil {
		t.Fatal(err)
	}
	d := newDiscoverer(rt, "docker")
	if _, _, err := d.Discover(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := newCompatClient("containerd", "/x"); err == nil {
		t.Fatal("unknown runtime accepted")
	}
}

func TestEnrollmentFromWorkloadLabels(t *testing.T) {
	good := containerSummary{ID: cidA, Names: []string{"/worker-01"}, Labels: map[string]string{
		labelWorkload: "worker-01", labelProfile: "diagnostic-worker", labelKind: "ai_worker", "river3.enroll": "false"}}
	en, err := enrollmentFromWorkloadLabels(good)
	if err != nil {
		t.Fatal(err)
	}
	if en.AssetID != "worker-01" || en.Name != "worker-01" || en.Profile != "diagnostic-worker" || en.Kind != "ai_worker" || en.ContainerID != cidA || en.Team != "" {
		t.Fatalf("%+v", en)
	}
	with := func(k, v string) containerSummary {
		c := good
		c.Labels = map[string]string{}
		for kk, vv := range good.Labels {
			c.Labels[kk] = vv
		}
		if v == "" {
			delete(c.Labels, k)
		} else {
			c.Labels[k] = v
		}
		return c
	}
	for name, c := range map[string]containerSummary{
		"no workload":   with(labelWorkload, ""),
		"bad workload":  with(labelWorkload, "has space"),
		"long workload": with(labelWorkload, strings.Repeat("w", 129)),
		"no profile":    with(labelProfile, ""),
		"bad profile":   with(labelProfile, "../etc"),
		"no kind":       with(labelKind, ""),
		"bad kind":      with(labelKind, "robot"),
		"team too long": with(labelTeam, strings.Repeat("t", 65)),
	} {
		if _, err := enrollmentFromWorkloadLabels(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	short := good
	short.ID = "aaaaaaaaaaaa"
	if _, err := enrollmentFromWorkloadLabels(short); err == nil {
		t.Error("short container id accepted")
	}
	named, _ := enrollmentFromWorkloadLabels(with(labelName, "Worker One"))
	if named.Name != "Worker One" {
		t.Fatal(named.Name)
	}
}

func TestDiscovererReportsOncePerIDAndAgainOnChange(t *testing.T) {
	rt := &fakeListRuntime{}
	rt.list = []containerSummary{{ID: cidC, Names: []string{"/bad"}, Labels: map[string]string{labelWorkload: "x y"}}}
	d := newDiscoverer(rt, "docker")
	ctx := context.Background()
	_, p1, _ := d.Discover(ctx)
	_, p2, _ := d.Discover(ctx)
	if len(p1) != 1 || len(p2) != 0 {
		t.Fatalf("%v %v", p1, p2)
	}
	// A different problem on the same id is news.
	rt.list[0].Labels = map[string]string{labelWorkload: "ok", labelProfile: "p", labelKind: "robot"}
	_, p3, _ := d.Discover(ctx)
	if len(p3) != 1 || !strings.Contains(p3[0], "river3.kind") {
		t.Fatalf("%v", p3)
	}
	// Fixed, then broken again: reported again.
	rt.list[0].Labels[labelKind] = "ai_worker"
	if found, p4, _ := d.Discover(ctx); len(found) != 1 || len(p4) != 0 {
		t.Fatalf("%+v %v", found, p4)
	}
	rt.list[0].Labels[labelKind] = "robot"
	if _, p5, _ := d.Discover(ctx); len(p5) != 1 {
		t.Fatalf("%v", p5)
	}
}

// fakeListRuntime is an in-memory ContainerRuntime for the label tests.
type fakeListRuntime struct {
	list []containerSummary
	err  error
}

func (f *fakeListRuntime) PID(context.Context, string) (uint32, error) { return 0, errNotRunning }
func (f *fakeListRuntime) List(context.Context) ([]containerSummary, error) {
	return f.list, f.err
}
func (f *fakeListRuntime) ListLabelled(context.Context, string) ([]containerSummary, error) {
	return f.list, f.err
}

func TestMergeEnrollmentsCapsDiscoveredAt1024(t *testing.T) {
	file := []Enrollment{{AssetID: "file-1", Name: "F", Profile: "p", Kind: "ai_worker", Mntns: 1}}
	var discovered []Enrollment
	for i := 0; i < maxEnrolled+10; i++ {
		discovered = append(discovered, Enrollment{AssetID: fmt.Sprintf("d-%04d", i), Name: "D", Profile: "p", Kind: "ai_worker", Mntns: uint32(100 + i)})
	}
	out, conflicts := mergeEnrollments(file, discovered)
	if len(out) != maxEnrolled || out[0].AssetID != "file-1" {
		t.Fatalf("len=%d first=%s", len(out), out[0].AssetID)
	}
	if len(conflicts) != 1 || !strings.Contains(conflicts[0], "11 discovered") {
		t.Fatalf("%v", conflicts)
	}
}

func TestMergeEnrollmentsFileWinsOverDiscovered(t *testing.T) {
	file := []Enrollment{{AssetID: "worker-01", Name: "File", Profile: "file-profile", Kind: "ai_worker", ContainerID: cidA}}
	discovered := []Enrollment{
		{AssetID: "other", Name: "L", Profile: "label-profile", Kind: "ai_worker", ContainerID: cidA, Discovered: "docker"},     // same container
		{AssetID: "worker-01", Name: "L", Profile: "label-profile", Kind: "ai_worker", ContainerID: cidB, Discovered: "docker"}, // same asset
		{AssetID: "svc-b", Name: "S", Profile: "p", Kind: "shared_service", ContainerID: cidC, Discovered: "docker"},
	}
	out, conflicts := mergeEnrollments(file, discovered)
	if len(out) != 2 || out[0].Profile != "file-profile" || out[1].AssetID != "svc-b" || out[1].Discovered != "docker" {
		t.Fatalf("%+v", out)
	}
	if len(conflicts) != 2 {
		t.Fatalf("%v", conflicts)
	}
}

func TestCombineDiscoveryEarlierSourceWins(t *testing.T) {
	a := func(context.Context) ([]Enrollment, []string, error) {
		return []Enrollment{{AssetID: "w", Name: "A", Profile: "p", Kind: "ai_worker", ContainerID: cidA}}, []string{"a-problem"}, nil
	}
	b := func(context.Context) ([]Enrollment, []string, error) {
		return []Enrollment{
			{AssetID: "w2", Name: "B", Profile: "p", Kind: "ai_worker", ContainerID: cidA, Discovered: "docker"},
			{AssetID: "x", Name: "B", Profile: "p", Kind: "ai_worker", ContainerID: cidB, Discovered: "docker"},
		}, nil, nil
	}
	out, problems, err := combineDiscovery(a, b)(context.Background())
	if err != nil || len(out) != 2 || out[0].Name != "A" || out[1].AssetID != "x" {
		t.Fatalf("%+v %v", out, err)
	}
	if len(problems) != 2 || problems[0] != "a-problem" {
		t.Fatalf("%v", problems)
	}
}

func TestWorkloadRegistrationCarriesDiscoveredLabel(t *testing.T) {
	body := workloadRegistration(Enrollment{AssetID: "w", Name: "W", Profile: "p", Kind: "ai_worker", Discovered: "podman", Team: "payments"})
	labels, ok := body["labels"].(map[string]string)
	if !ok || labels["discovered"] != "podman" || body["team"] != "payments" || body["sensor"] != "ebpf" {
		t.Fatalf("%v", body)
	}
	if _, has := workloadRegistration(Enrollment{AssetID: "w"})["labels"]; has {
		t.Fatal("file enrollment must not carry labels")
	}
}

func TestEnrollerKickRefreshesImmediately(t *testing.T) {
	var refreshes atomic.Int32
	e := &Enroller{
		Discover: func(context.Context) ([]Enrollment, []string, error) { refreshes.Add(1); return nil, nil, nil },
		Watch:    newWatchlist(),
		Log:      func(string, ...any) {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, time.Hour) // the ticker alone would never fire in this test
	e.Kick()
	e.Kick() // coalesces with the first
	deadline := time.Now().Add(2 * time.Second)
	for refreshes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if refreshes.Load() == 0 {
		t.Fatal("kick did not refresh")
	}
	time.Sleep(300 * time.Millisecond)
	if n := refreshes.Load(); n > 2 {
		t.Fatalf("two kicks caused %d refreshes", n)
	}
}
