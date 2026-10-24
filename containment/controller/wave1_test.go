package controller

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/apiclient"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// --- (b) operator claim lost after a crash --------------------------------------------

// claimedJournal writes a journal in which an operator request was claimed and the
// process died before FinishOperator: the exact state a crash mid-action leaves.
func claimedJournal(t *testing.T, actionID, action string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "crashed.jsonl")
	j, err := journal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimOperator(actionID, map[string]any{"action": action, "workload_id": "worker-01", "operator": "rajiv", "source": "poll"}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	return p
}

func TestOperatorResumeClaimIsReExecutedOnRestartAndReported(t *testing.T) {
	jpath := claimedJournal(t, "act_crash", "resume")
	// The runtime is still paused: the resume never went out (or did not take). The
	// operator asked for the workload to run; a restart must not leave it frozen.
	r := newRig(t, withJournal(jpath), func(r *rig, _ *Config) { r.mock.Add(cidWorker, "generation-1", adapter.Paused) })

	o, ok := r.c.Journal().Operator("act_crash")
	if !ok || o.Result != "completed" || o.Detail["workload_state"] != "running" || o.Detail["reconciled"] != true ||
		o.Detail["note"] != "re-executed after controller restart" || o.Detail["operator"] != "rajiv" {
		t.Fatalf("claim not settled by re-execution: %+v", o)
	}
	if r.state(cidWorker) != adapter.Running || len(r.mock.Calls()) != 1 || r.mock.Calls()[0] != "resume:"+cidWorker {
		t.Fatalf("resume not re-run exactly once: %s %v", r.state(cidWorker), r.mock.Calls())
	}
	res, ok := r.api.result("act_crash")
	if !ok || res.Status != "completed" || res.WorkloadState != "running" || res.Detail["operator"] != "rajiv" {
		t.Fatalf("result not reported to the API: %+v %v", res, ok)
	}
	if len(r.c.Journal().HandlingOperators()) != 0 {
		t.Fatal("still in flight")
	}
	// A redelivery of the same request from the API is still a duplicate: no second resume.
	if out := r.c.HandleOperatorAction(context.Background(), resumeReq("act_crash"), "poll"); out != OpDuplicate {
		t.Fatalf("redelivery: %s", out)
	}
	if len(r.mock.Calls()) != 1 {
		t.Fatalf("redelivery acted: %v", r.mock.Calls())
	}
}

func TestOperatorResumeClaimOnStaleGenerationIsFailedNotForced(t *testing.T) {
	jpath := claimedJournal(t, "act_stale", "resume")
	// Re-execution goes through the same checks as a fresh request: a container that
	// was replaced while the controller was down is not touched.
	r := newRig(t, withJournal(jpath), func(r *rig, _ *Config) { r.mock.Add(cidWorker, "generation-2", adapter.Paused) })
	o, _ := r.c.Journal().Operator("act_stale")
	if o.Result != "failed" || !strings.Contains(o.Detail["reason"].(string), "STALE_GENERATION") || o.Detail["reconciled"] != true {
		t.Fatalf("%+v", o)
	}
	if len(r.mock.Calls()) != 0 || r.state(cidWorker) != adapter.Paused {
		t.Fatalf("stale container was acted on: %v", r.mock.Calls())
	}
	if res, ok := r.api.result("act_stale"); !ok || res.Status != "failed" {
		t.Fatalf("%+v %v", res, ok)
	}
}

func TestOperatorTerminateClaimIsFailedOnRestartAndNeverReRun(t *testing.T) {
	jpath := claimedJournal(t, "act_kill", "terminate")
	// The stop never went out: the container is still running. A restart must not kill
	// it on its own; the operator is told and can ask again.
	r := newRig(t, withJournal(jpath))

	o, ok := r.c.Journal().Operator("act_kill")
	if !ok || o.Result != "failed" || o.Detail["reason"] != "controller restarted mid-action" || o.Detail["reconciled"] != true {
		t.Fatalf("claim not settled: %+v", o)
	}
	if r.state(cidWorker) != adapter.Running || len(r.mock.Calls()) != 0 {
		t.Fatalf("a terminate was re-run after a restart: %s %v", r.state(cidWorker), r.mock.Calls())
	}
	res, ok := r.api.result("act_kill")
	if !ok || res.Status != "failed" || res.Detail["reason"] != "controller restarted mid-action" || res.Detail["operator"] != "rajiv" {
		t.Fatalf("result not reported to the API: %+v %v", res, ok)
	}
	if len(r.c.Journal().HandlingOperators()) != 0 {
		t.Fatal("still in flight")
	}
	// Redelivery from the API is a duplicate; the operator has to request a new action.
	req := resumeReq("act_kill")
	req.Action = "terminate"
	if out := r.c.HandleOperatorAction(context.Background(), req, "poll"); out != OpDuplicate || len(r.mock.Calls()) != 0 {
		t.Fatalf("redelivery: %s %v", out, r.mock.Calls())
	}
}

func TestOperatorClaimSettledCompletedWhenRuntimeAlreadyShowsIt(t *testing.T) {
	jpath := claimedJournal(t, "act_done", "resume")
	// The unpause went out before the crash: the container is running again, so the
	// re-executed resume is a no-op and says so.
	r := newRig(t, withJournal(jpath))
	o, _ := r.c.Journal().Operator("act_done")
	if o.Result != "completed" || o.Detail["workload_state"] != "running" || !strings.Contains(o.Detail["note"].(string), "settled after controller restart") {
		t.Fatalf("%+v", o)
	}
	if len(r.mock.Calls()) != 0 {
		t.Fatalf("a running container was acted on: %v", r.mock.Calls())
	}
	res, ok := r.api.result("act_done")
	if !ok || res.Status != "completed" || res.WorkloadState != "running" {
		t.Fatalf("%+v %v", res, ok)
	}
}

func TestOperatorClaimForUnknownWorkloadIsFailedNotGuessed(t *testing.T) {
	jpath := claimedJournal(t, "act_gone", "terminate")
	r := newRig(t, withJournal(jpath), func(r *rig, _ *Config) { r.mock.Remove(cidWorker) })
	o, _ := r.c.Journal().Operator("act_gone")
	// Missing after a terminate is exactly what a completed terminate looks like.
	if o.Result != "completed" || o.Detail["workload_state"] != "terminated" {
		t.Fatalf("%+v", o)
	}
	// A claim whose journaled request is unusable can only be failed.
	p := filepath.Join(t.TempDir(), "bare.jsonl")
	j, _ := journal.Open(p)
	_, _ = j.ClaimOperator("act_bare", nil)
	j.Close()
	r2 := newRig(t, withJournal(p))
	if o, _ := r2.c.Journal().Operator("act_bare"); o.Result != "failed" {
		t.Fatalf("%+v", o)
	}
}

// --- (c) double flush ----------------------------------------------------------------

func TestConcurrentFlushNeverDoublePostsAnIncident(t *testing.T) {
	for run := 0; run < 30; run++ {
		r := newRig(t)
		r.api.setDown(true)
		mustState(t, r.handle(r.event("ev-dbl", "file_open", decoyOpen("x"), "success")), journal.Verified)
		if r.api.incidentPosts() != 0 {
			t.Fatal("nothing should have reached the API while it was down")
		}
		r.api.setDown(false)

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				r.c.Flush(context.Background())
			}()
		}
		close(start)
		wg.Wait()

		ev, _ := r.c.Journal().Event("ev-dbl")
		if ev.Orphaned {
			t.Fatalf("run %d: event orphaned by a double POST", run)
		}
		if posts := r.api.incidentPosts(); posts != 1 {
			t.Fatalf("run %d: incident POSTed %d times", run, posts)
		}
		if ev.IncidentID == "" || !ev.ResponseDone || r.api.patchCount() != 1 {
			t.Fatalf("run %d: flush incomplete: %+v patches=%d", run, ev, r.api.patchCount())
		}
		// The in-flight set is empty again: a stuck entry would silence the outbox forever.
		r.c.flushMu.Lock()
		left := len(r.c.flushing)
		r.c.flushMu.Unlock()
		if left != 0 {
			t.Fatalf("run %d: %d keys left in flight", run, left)
		}
	}
}

func TestConcurrentOperatorReportIsPostedOnce(t *testing.T) {
	r := newRig(t)
	r.api.setDown(true)
	mustState(t, r.handle(r.event("ev-op", "file_open", decoyOpen("x"), "success")), journal.Verified)
	if out := r.c.HandleOperatorAction(context.Background(), resumeReq("act_once"), "test"); out != OpCompleted {
		t.Fatal(out)
	}
	r.api.setDown(false)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.c.Flush(context.Background()) }()
	}
	wg.Wait()
	if _, ok := r.api.result("act_once"); !ok {
		t.Fatal("operator result never reported")
	}
	if o, _ := r.c.Journal().Operator("act_once"); !o.Reported {
		t.Fatal("not marked reported")
	}
}

// --- (d) policy cache on first start ---------------------------------------------------

func TestStartupPolicyWritesCacheWhenTheSetComesFromTheAPI(t *testing.T) {
	r := newRig(t)
	r.api.setBundle(revA, rawProfile(t, activeProfile()), rawProfile(t, sharedProfile()))
	api, _ := apiclient.New(apiclient.Config{BaseURL: r.api.srv.URL, ContainmentToken: "m-contain", PolicyToken: "m-policy", MaxAttempts: 1, Backoff: time.Millisecond})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := filepath.Join(t.TempDir(), "j.policy.json")

	p, source := StartupPolicy(context.Background(), log, api, r.reg, cache)
	if p == nil || source != "api" || p.Revision != revA {
		t.Fatalf("%+v %s", p, source)
	}
	b, err := LoadPolicyCache(cache)
	if err != nil || b.Revision != revA || len(b.Profiles) != 2 {
		t.Fatalf("cache not written on first start: %+v %v", b, err)
	}

	// Restart while the API is down: the cached console policy is used, not the files.
	r.api.setDown(true)
	p, source = StartupPolicy(context.Background(), log, api, r.reg, cache)
	if p == nil || source != "cache" || p.Revision != revA {
		t.Fatalf("cache not used: %+v %s", p, source)
	}

	// No cache and no API: nil, so main falls back to -profiles.
	if p, source = StartupPolicy(context.Background(), log, api, r.reg, filepath.Join(t.TempDir(), "none.json")); p != nil || source != "" {
		t.Fatalf("%+v %s", p, source)
	}
	// A rejected API set (a workload would lose its profile) is neither used nor cached.
	r.api.setDown(false)
	r.api.setBundle(revB, rawProfile(t, activeProfile()))
	fresh := filepath.Join(t.TempDir(), "fresh.json")
	if p, _ = StartupPolicy(context.Background(), log, api, r.reg, fresh); p != nil {
		t.Fatal("rejected set used")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("rejected set cached")
	}
}

// --- §9 blocked outcome -----------------------------------------------------------------

func TestBlockedDecoyOpenAlertsAndNamesTheInlineBlock(t *testing.T) {
	r := newRig(t)
	out := r.handle(r.event("ev-blk", "file_open", decoyOpen("x"), "blocked"))
	if out.Status != policy.Violation || out.Action != policy.Alert || out.Candidate {
		t.Fatalf("a blocked decoy read is a violation that needs no pause: %+v", out)
	}
	if !contains(out.Blockers, "OUTCOME_NOT_SUCCESSFUL") {
		t.Fatalf("blockers %v", out.Blockers)
	}
	if r.state(cidWorker) != adapter.Running || len(r.mock.Calls()) != 0 {
		t.Fatal("adapter must not be called: the sensor already blocked the operation")
	}
	inc, ok := r.api.incident(out.IncidentID)
	if !ok {
		t.Fatalf("incident not posted: %+v", out)
	}
	reason, _ := inc["reason"].(string)
	if !strings.Contains(reason, normalize.BlockedNote) {
		t.Fatalf("reason does not mention the inline block: %q", reason)
	}
	evs := inc["events"].([]any)
	facts := evs[0].(map[string]any)["facts"].(map[string]any)
	if facts["blocked_inline"] != true || facts["outcome"] != "FAILED" {
		t.Fatalf("facts %v", facts)
	}
}

// --- §4.2 discovery (fake runtime) ------------------------------------------------------

type fakeLister struct {
	mu   sync.Mutex
	rows []registry.Container
	err  error
}

func (f *fakeLister) ListEnrolled(context.Context) ([]registry.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]registry.Container(nil), f.rows...), nil
}

func (f *fakeLister) set(rows ...registry.Container) {
	f.mu.Lock()
	f.rows = rows
	f.mu.Unlock()
}

func ctr(id, asset, kind, gen string) registry.Container {
	return registry.Container{ID: id, Name: "/" + asset, Generation: gen, Labels: map[string]string{
		"river3.enroll": "true", "river3.asset_id": asset, "river3.kind": kind,
		"river3.profile": map[string]string{"ai_worker": "diagnostic-worker", "shared_service": "payment-service"}[kind]}}
}

func baseFile(t *testing.T) registry.File {
	t.Helper()
	f, err := registry.LoadFile(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.Workloads = nil
	return f
}

func TestDiscoverySwapsRegistryAndFollowsRestarts(t *testing.T) {
	base := baseFile(t)
	empty, err := registry.New(base)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, withRegistry(empty))
	src := &fakeLister{}
	d := &Discovery{Source: src, Base: base}

	// Nothing labelled yet: an empty set is a valid snapshot.
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	src.set(ctr(cidWorker, "worker-01", "ai_worker", "generation-1"), ctr(cidPayments, "payments-01", "shared_service", "generation-1"))
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	reg := r.c.Registry().Get()
	w, ok := reg.Workload("worker-01")
	if !ok || w.Generation != "generation-1" || !w.Dedicated || len(w.PermittedActions) != 1 {
		t.Fatalf("%+v %v", w, ok)
	}
	if p, ok := reg.Workload("payments-01"); !ok || p.Dedicated || len(p.PermittedActions) != 0 {
		t.Fatalf("%+v", p)
	}
	// The discovered worker is now a real target: a decoy read pauses it.
	mustState(t, r.handle(r.event("ev-disc", "file_open", decoyOpen("x"), "success")), journal.Verified)

	// Same set again: no swap (pointer identity), no change.
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil || r.c.Registry().Get() != reg {
		t.Fatal("unchanged runtime must not swap the snapshot")
	}

	// A restart: the mock runtime and the listing both show the new generation.
	r.mock.Replace(cidWorker, "generation-2")
	src.set(ctr(cidWorker, "worker-01", "ai_worker", "generation-2"), ctr(cidPayments, "payments-01", "shared_service", "generation-1"))
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if w, _ := r.c.Registry().Get().Workload("worker-01"); w.Generation != "generation-2" {
		t.Fatalf("generation not followed: %+v", w)
	}
	mustState(t, r.handle(r.event("ev-disc-2", "file_open", decoyOpen("x"), "success")), journal.Verified)

	// The payments container goes away: removed; a listing error keeps the last snapshot.
	src.set(ctr(cidWorker, "worker-01", "ai_worker", "generation-2"))
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.Registry().Get().Workload("payments-01"); ok {
		t.Fatal("removed container still enrolled")
	}
	kept := r.c.Registry().Get()
	src.mu.Lock()
	src.err = context.DeadlineExceeded
	src.mu.Unlock()
	if err := r.c.DiscoverOnce(context.Background(), d); err == nil || r.c.Registry().Get() != kept {
		t.Fatal("a listing failure must keep the last good snapshot")
	}
}

func TestDiscoverySkipsUnknownProfileAndKeepsSensors(t *testing.T) {
	base := baseFile(t)
	empty, _ := registry.New(base)
	r := newRig(t, withRegistry(empty))
	bad := ctr(cidWorker, "worker-01", "ai_worker", "generation-1")
	bad.Labels["river3.profile"] = "not-loaded"
	src := &fakeLister{rows: []registry.Container{bad, ctr(cidPayments, "payments-01", "shared_service", "generation-1")}}
	if err := r.c.DiscoverOnce(context.Background(), &Discovery{Source: src, Base: base}); err != nil {
		t.Fatal(err)
	}
	reg := r.c.Registry().Get()
	if _, ok := reg.Workload("worker-01"); ok {
		t.Fatal("a workload bound to a profile the engine lacks must not be enrolled")
	}
	if _, ok := reg.Workload("payments-01"); !ok {
		t.Fatal("the valid container must still be enrolled")
	}
	if _, ok := reg.Authenticate(sensorToken); !ok {
		t.Fatal("sensors must come from the file")
	}
	// Policy sync still works: the skipped container does not hold the node hostage.
	r.api.setBundle(revA, rawProfile(t, activeProfile()), rawProfile(t, sharedProfile()))
	if err := r.c.SyncPolicy(context.Background()); err != nil || r.c.Policy().Revision != revA {
		t.Fatalf("%v %+v", err, r.c.Policy())
	}
}
