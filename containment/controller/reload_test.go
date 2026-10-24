package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

const cidWorker2 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// --- §5 registry hot reload -----------------------------------------------------------

// registryV1 is the fixture file copied to a temp path the test can rewrite.
func registryV1(t *testing.T) (string, registry.File) {
	t.Helper()
	f, err := registry.LoadFile(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "registry.json")
	writeRegistry(t, p, f, 1)
	return p, f
}

// writeRegistry writes the file with a distinct mtime per version: a filesystem with
// coarse timestamps could otherwise hand two writes in one test the same mtime.
func writeRegistry(t *testing.T, path string, f registry.File, version int) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2026, 10, 22, 8, 0, version, 0, time.UTC)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func worker02() registry.Workload {
	return registry.Workload{AssetID: "worker-02", Name: "Diagnostic worker 02", Profile: "diagnostic-worker", Kind: "ai_worker",
		ContainerID: cidWorker2, Generation: "generation-1", Dedicated: true, Active: true, PermittedActions: []policy.Action{policy.Pause}}
}

// worker02Event is a decoy read from the not-yet-enrolled second worker.
func (r *rig) worker02Event(id string) normalize.Envelope {
	env := r.event(id, "file_open", decoyOpen("x"), "success")
	env.Raw.Facts.Workload.ID = "worker-02"
	env.Raw.Facts.Workload.ContainerID = cidWorker2
	return env
}

func healthz(t *testing.T, r *rig) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	(&Server{C: r.c}).Handler().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRegistryReloadEnrolsNewWorkloadAndNeverSwapsInAnInvalidFile(t *testing.T) {
	path, v1 := registryV1(t)
	reg, err := registry.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, withRegistry(reg))
	r.mock.Add(cidWorker2, "generation-1", adapter.Running)
	if err := r.c.WatchRegistry(&RegistryReload{Path: path}); err != nil {
		t.Fatal(err)
	}
	if h := healthz(t, r); h["registry_error"] != "" || h["registry"].(map[string]any)["workloads"] != float64(2) {
		t.Fatalf("healthz before any reload: %v", h)
	}

	// v1: worker-02 is unknown to this node, so its decoy read only alerts.
	if out := r.handle(r.worker02Event("ev-w2-before")); !out.Unenrolled || out.Candidate {
		t.Fatalf("unenrolled workload acted on: %+v", out)
	}

	// v2 adds the workload. Reload directly (what SIGHUP does): the next event is enrolled
	// and contained, which proves the normalizer reads through the Holder, not a copy.
	v2 := v1
	v2.Workloads = append(append([]registry.Workload(nil), v1.Workloads...), worker02())
	writeRegistry(t, path, v2, 2)
	if err := r.c.ReloadRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.Registry().Get().Workload("worker-02"); !ok {
		t.Fatal("v2 not swapped in")
	}
	mustState(t, r.handle(r.worker02Event("ev-w2-after")), journal.Verified)
	if r.state(cidWorker2) != adapter.Paused {
		t.Fatal("new workload not paused")
	}
	// The operator path reads through the Holder too.
	req := resumeReq("act_w2")
	req.WorkloadID = "worker-02"
	if out := r.c.HandleOperatorAction(context.Background(), req, "test"); out != OpCompleted || r.state(cidWorker2) != adapter.Running {
		t.Fatalf("operator resume on the reloaded workload: %s %s", out, r.state(cidWorker2))
	}
	current := r.c.Registry().Get()

	// v3 is invalid (short container id). The poll sees the mtime change, the loader
	// refuses the file, v2 stays, and /healthz says why.
	v3 := v2
	bad := worker02()
	bad.AssetID, bad.ContainerID = "worker-03", "deadbeef"
	v3.Workloads = append(append([]registry.Workload(nil), v2.Workloads...), bad)
	writeRegistry(t, path, v3, 3)
	changed, err := r.c.PollRegistry(context.Background())
	if !changed || err == nil || !strings.Contains(err.Error(), "container_id") {
		t.Fatalf("invalid file: changed=%v err=%v", changed, err)
	}
	if r.c.Registry().Get() != current {
		t.Fatal("an invalid file replaced the registry")
	}
	h := healthz(t, r)
	if e, _ := h["registry_error"].(string); !strings.Contains(e, "container_id") || h["ok"] != true {
		t.Fatalf("healthz after rejection: %v", h)
	}
	// Unchanged since: no second attempt, the error stays visible.
	if changed, err := r.c.PollRegistry(context.Background()); changed || err != nil {
		t.Fatalf("unchanged file re-read: %v %v", changed, err)
	}
	if h := healthz(t, r); h["registry_error"] == "" {
		t.Fatal("rejection cleared without a new file")
	}

	// A workload bound to a profile the enforced set lacks is refused whole, for the same
	// reason BuildPolicy refuses a set that would orphan a workload.
	v4 := v2
	orphan := worker02()
	orphan.AssetID, orphan.ContainerID, orphan.Profile = "worker-04", strings.Repeat("d", 64), "not-loaded"
	v4.Workloads = append(append([]registry.Workload(nil), v2.Workloads...), orphan)
	writeRegistry(t, path, v4, 4)
	if _, err := r.c.PollRegistry(context.Background()); err == nil || !strings.Contains(err.Error(), `"not-loaded"`) || r.c.Registry().Get() != current {
		t.Fatalf("unknown profile accepted: %v", err)
	}

	// A valid file again: applied, error cleared, diff logged (removed worker-01 here).
	v5 := v2
	v5.Workloads = []registry.Workload{worker02()}
	writeRegistry(t, path, v5, 5)
	if changed, err := r.c.PollRegistry(context.Background()); !changed || err != nil {
		t.Fatalf("valid file not applied: %v %v", changed, err)
	}
	if _, ok := r.c.Registry().Get().Workload("worker-01"); ok {
		t.Fatal("removed workload still enrolled")
	}
	h = healthz(t, r)
	if h["registry_error"] != "" || h["registry"].(map[string]any)["reloads"] != float64(2) || h["registry"].(map[string]any)["workloads"] != float64(1) {
		t.Fatalf("healthz after recovery: %v", h)
	}
	// worker-01 is gone from this node: its events are now unenrolled, alert only.
	if out := r.handle(r.event("ev-w1-gone", "file_open", decoyOpen("x"), "success")); !out.Unenrolled || len(r.mock.Calls()) != 2 {
		t.Fatalf("un-enrolled workload acted on: %+v %v", out, r.mock.Calls())
	}
}

func TestRegistryReloadCompareNamesEveryKindOfChange(t *testing.T) {
	_, v1 := registryV1(t)
	prev, _ := registry.New(v1)
	v2 := v1
	v2.Sensors = append([]registry.Sensor{{Name: "second", TokenSHA256: strings.Repeat("ab", 32), ResolvesPaths: false}}, v1.Sensors...)
	changed := v1.Workloads[0]
	changed.PermittedActions = nil // same container and generation; only the permissions moved
	v2.Workloads = []registry.Workload{changed, worker02()}
	next, err := registry.New(v2)
	if err != nil {
		t.Fatal(err)
	}
	ch := registry.Compare(prev, next)
	if strings.Join(ch.Added, ",") != "worker-02" || strings.Join(ch.Removed, ",") != "payments-01" || strings.Join(ch.Changed, ",") != "worker-01" ||
		strings.Join(ch.SensorsAdded, ",") != "second" || len(ch.SensorsRemoved) != 0 || ch.Empty() {
		t.Fatalf("%+v", ch)
	}
	if !registry.Compare(prev, prev).Empty() {
		t.Fatal("identical snapshots differ")
	}
}

func TestRegistryReloadOnSIGHUP(t *testing.T) {
	path, v1 := registryV1(t)
	reg, _ := registry.Load(path)
	r := newRig(t, withRegistry(reg))
	r.mock.Add(cidWorker2, "generation-1", adapter.Running)
	// Every = 0: polling off, the signal is the only trigger.
	if err := r.c.WatchRegistry(&RegistryReload{Path: path}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hup := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() { r.c.RunRegistryReload(ctx, hup); close(done) }()

	v2 := v1
	v2.Workloads = append(append([]registry.Workload(nil), v1.Workloads...), worker02())
	writeRegistry(t, path, v2, 2)
	// Without the signal nothing happens (no poll): give the loop a moment to prove it.
	time.Sleep(20 * time.Millisecond)
	if _, ok := r.c.Registry().Get().Workload("worker-02"); ok {
		t.Fatal("reloaded without a trigger while polling is off")
	}
	hup <- syscall.SIGHUP
	waitFor(t, func() bool { _, ok := r.c.Registry().Get().Workload("worker-02"); return ok }, "SIGHUP reload")
	mustState(t, r.handle(r.worker02Event("ev-hup")), journal.Verified)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reload loop did not stop")
	}
}

func TestRegistryReloadPollPicksUpAnEditAndKeepsV2OnABadV3(t *testing.T) {
	path, v1 := registryV1(t)
	reg, _ := registry.Load(path)
	r := newRig(t, withRegistry(reg))
	r.mock.Add(cidWorker2, "generation-1", adapter.Running)
	if err := r.c.WatchRegistry(&RegistryReload{Path: path, Every: 5 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.c.RunRegistryReload(ctx, nil) // nil hup: signal path off, ticker only

	v2 := v1
	v2.Workloads = append(append([]registry.Workload(nil), v1.Workloads...), worker02())
	writeRegistry(t, path, v2, 2)
	waitFor(t, func() bool { _, ok := r.c.Registry().Get().Workload("worker-02"); return ok }, "poll reload")
	v2reg := r.c.Registry().Get()

	// v3 is not even JSON: the editor's half-written save. v2 stays, the error shows.
	if err := os.WriteFile(path, []byte(`{"node": {"tenant_id": "lab",`), 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2026, 10, 22, 8, 0, 3, 0, time.UTC)
	_ = os.Chtimes(path, mt, mt)
	waitFor(t, func() bool { _, e := r.c.RegistryStatus(); return e != "" }, "rejection recorded")
	if r.c.Registry().Get() != v2reg {
		t.Fatal("v2 replaced by an invalid v3")
	}
	mustState(t, r.handle(r.worker02Event("ev-poll")), journal.Verified)
}

func TestRegistryReloadWithDiscoveryReplacesSensorsOnly(t *testing.T) {
	base := baseFile(t)
	empty, _ := registry.New(base)
	r := newRig(t, withRegistry(empty))
	src := &fakeLister{rows: []registry.Container{ctr(cidWorker, "worker-01", "ai_worker", "generation-1")}}
	d := &Discovery{Source: src, Base: base}
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	writeRegistry(t, path, base, 1)
	if err := r.c.WatchRegistry(&RegistryReload{Path: path, Discovery: d}); err != nil {
		t.Fatal(err)
	}

	// v2: a second sensor, plus a static workload that must stay ignored in this mode.
	sum := sha256.Sum256([]byte("second-token"))
	v2 := base
	v2.Sensors = append([]registry.Sensor{{Name: "second-sensor", TokenSHA256: hex.EncodeToString(sum[:]), ResolvesPaths: true}}, base.Sensors...)
	v2.Workloads = []registry.Workload{worker02()}
	writeRegistry(t, path, v2, 2)
	if err := r.c.ReloadRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	reg := r.c.Registry().Get()
	if _, ok := reg.Authenticate("second-token"); !ok {
		t.Fatal("new sensor not enrolled")
	}
	if _, ok := reg.Authenticate(sensorToken); !ok {
		t.Fatal("existing sensor lost")
	}
	if _, ok := reg.Workload("worker-01"); !ok {
		t.Fatal("runtime-discovered workload lost on file reload")
	}
	if _, ok := reg.Workload("worker-02"); ok {
		t.Fatal("static workload enrolled although workloads come from the runtime")
	}

	// v3 drops the token hash: refused, v2 stays, and the next discovery pass still uses v2.
	v3 := v2
	v3.Sensors = []registry.Sensor{{Name: "broken"}}
	writeRegistry(t, path, v3, 3)
	if changed, err := r.c.PollRegistry(context.Background()); !changed || err == nil || r.c.Registry().Get() != reg {
		t.Fatalf("invalid sensor file: %v %v", changed, err)
	}
	src.set(ctr(cidWorker, "worker-01", "ai_worker", "generation-2"))
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.Registry().Get().Authenticate("second-token"); !ok {
		t.Fatal("rejected file leaked into the discovery base")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
