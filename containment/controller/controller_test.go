package controller

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	policy "river3.local/policy"
)

// --- the happy path: decoy open → one verified pause → reported ----------------

func TestDecoyOpenPausesVerifiesAndReports(t *testing.T) {
	r := newRig(t)
	out := r.handle(r.event("ev-1", "file_open", decoyOpen("ev-1"), "success"))

	if out.Status != policy.Violation || out.Action != policy.Pause || !out.Candidate {
		t.Fatalf("decision: %+v", out)
	}
	mustState(t, out, journal.Verified)
	if r.state(cidWorker) != adapter.Paused {
		t.Fatal("container not paused")
	}
	if calls := r.mock.Calls(); len(calls) != 1 || calls[0] != "pause:"+cidWorker {
		t.Fatalf("adapter calls: %v", calls)
	}
	if out.IncidentID == "" {
		t.Fatal("incident not created")
	}
	p, ok := r.api.lastPatch()
	if !ok || p.IncidentID != out.IncidentID {
		t.Fatalf("response not reported: %+v", p)
	}
	if p.Body.Status != "contained" || p.Body.WorkloadState != "frozen" {
		t.Fatalf("patch body: %+v", p.Body)
	}
	if p.Body.Response["state"] != "verified" || p.Body.Response["action"] != "PAUSE_CONTAINER" || p.Body.Response["idempotency_key"] != out.Key {
		t.Fatalf("response payload: %+v", p.Body.Response)
	}
	obs := p.Body.Response["observed"].(map[string]any)
	if obs["status"] != "paused" {
		t.Fatalf("observed: %+v", obs)
	}
	st := r.c.Journal().Stats()
	if st.Verified != 1 || st.PendingReports != 0 || st.Orphaned != 0 {
		t.Fatalf("journal stats %+v", st)
	}
}

func TestBenignReadIsInScopeAndSilent(t *testing.T) {
	r := newRig(t)
	out := r.handle(r.event("ev-ok", "file_open", normalize.RawTarget{Path: "/var/log/app/error.log", PathResolved: true, Access: "read"}, "success"))
	if out.Status != policy.InScope || out.Candidate || out.IncidentID != "" {
		t.Fatalf("%+v", out)
	}
	if len(r.mock.Calls()) != 0 || r.api.patchCount() != 0 {
		t.Fatal("in-scope event must not touch the runtime or the API")
	}
}

// --- duplicates and replay ------------------------------------------------------

func TestDuplicateEventNeverPausesTwice(t *testing.T) {
	r := newRig(t)
	env := r.event("ev-dup", "file_open", decoyOpen("ev-dup"), "success")
	first := r.handle(env)
	mustState(t, first, journal.Verified)

	// The same event arrives again (sensor retry) with the container already paused.
	again := r.handle(env)
	if !again.Duplicate {
		t.Fatalf("expected duplicate, got %+v", again)
	}
	mustState(t, again, journal.Verified)
	if again.IncidentID != first.IncidentID || again.Key != first.Key {
		t.Fatal("duplicate must point at the original incident and key")
	}
	if len(r.mock.Calls()) != 1 {
		t.Fatalf("adapter called %d times", len(r.mock.Calls()))
	}
	if r.api.patchCount() != 1 {
		t.Fatalf("response patched %d times", r.api.patchCount())
	}
}

func TestSameEvidenceDifferentEventIDIsBlockedNotRepeated(t *testing.T) {
	// A second decoy open after the pause: the container is now paused, so the
	// refreshed context is not Active and the engine blocks (WORKLOAD_NOT_READY).
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-a", "file_open", decoyOpen("ev-a"), "success")), journal.Verified)
	out := r.handle(r.event("ev-b", "file_open", decoyOpen("ev-b"), "success"))
	if out.Candidate || out.Action != policy.Alert || !contains(out.Blockers, "WORKLOAD_NOT_READY") {
		t.Fatalf("%+v", out)
	}
	if len(r.mock.Calls()) != 1 {
		t.Fatal("second pause attempted")
	}
}

// --- the adapter's word is never the result ------------------------------------

func TestAdapterReturnsOKButRuntimeUnchangedIsFailed(t *testing.T) {
	r := newRig(t)
	r.mock.PauseNoEffect = true
	out := r.handle(r.event("ev-lie", "file_open", decoyOpen("ev-lie"), "success"))
	mustState(t, out, journal.Failed)
	p, _ := r.api.lastPatch()
	if p.Body.Status != "" || p.Body.WorkloadState != "" || p.Body.Response["state"] != "failed" {
		t.Fatalf("a failed pause must not mark the incident contained: %+v", p.Body)
	}
}

func TestAdapterErrorIsFailedWithRuntimeEvidence(t *testing.T) {
	r := newRig(t)
	r.mock.PauseErr = errors.New("runtime: permission denied")
	out := r.handle(r.event("ev-err", "file_open", decoyOpen("ev-err"), "success"))
	mustState(t, out, journal.Failed)
	a, _ := r.c.Journal().Action(out.Key)
	if a.Detail["adapter_error"] != "runtime: permission denied" || a.Detail["observed"].(map[string]any)["status"] != "running" {
		t.Fatalf("detail %+v", a.Detail)
	}
}

func TestInspectionFailureAfterPauseIsUnknown(t *testing.T) {
	r := newRig(t)
	r.mock.InspectErrAfterMutation = errors.New("runtime: socket closed")
	out := r.handle(r.event("ev-unk", "file_open", decoyOpen("ev-unk"), "success"))
	mustState(t, out, journal.Unknown)
	p, _ := r.api.lastPatch()
	if p.Body.WorkloadState != "unknown" || p.Body.Status != "" {
		t.Fatalf("unknown outcome must report workload state unknown, not contained: %+v", p.Body)
	}
}

func TestTransitionalRuntimeStateAfterPauseIsUnknownNotFailed(t *testing.T) {
	r := newRig(t)
	// Inspect #1 evaluates, #2 refreshes before Revalidate, #3 verifies after the
	// pause. The runtime answers #3 with a state this controller has no name for
	// (podman "pausing"): that is neither proof of success nor of failure.
	r.mock.InspectHook = func(call int) {
		if call == 3 {
			r.mock.Add(cidWorker, "generation-1", adapter.Unknown)
		}
	}
	out := r.handle(r.event("ev-trans", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Unknown)
	a, _ := r.c.Journal().Action(out.Key)
	if a.Detail["observed"].(map[string]any)["status"] != "unknown" || a.Detail["reason"] == nil {
		t.Fatalf("detail %+v", a.Detail)
	}
	p, _ := r.api.lastPatch()
	if p.Body.WorkloadState != "unknown" || p.Body.Status != "" || p.Body.Response["state"] != "unknown" {
		t.Fatalf("transitional state must report workload_state unknown, never contained or failed: %+v", p.Body)
	}
}

func TestContainerGoneAfterPauseIsFailed(t *testing.T) {
	r := newRig(t)
	r.mock.InspectHook = func(call int) {
		if call == 3 {
			r.mock.Remove(cidWorker) // Missing is a definite answer: the pause did not hold
		}
	}
	out := r.handle(r.event("ev-gone", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Failed)
	p, _ := r.api.lastPatch()
	if p.Body.Status != "" || p.Body.Response["state"] != "failed" {
		t.Fatalf("%+v", p.Body)
	}
}

// --- sensor liveness ---------------------------------------------------------------

func withHeartbeat(d time.Duration) rigOpt {
	return func(_ *rig, c *Config) { c.HeartbeatWithin = d }
}

func TestSilentSensorBlocksAutomaticAction(t *testing.T) {
	r := newRig(t, withHeartbeat(10*time.Minute))
	// The sensor's first message arrives right after start: healthy, and in scope.
	out := r.handle(r.event("ev-hb1", "file_open", normalize.RawTarget{Path: "/var/log/app/error.log", PathResolved: true, Access: "read"}, "success"))
	if out.Status != policy.InScope {
		t.Fatalf("%+v", out)
	}
	// An hour of silence, then a decoy read. The liveness check must be judged
	// against the PREVIOUS heartbeat, not the message that carries the violation;
	// a controller that stamped the heartbeat first could never see a silent sensor.
	r.now = r.now.Add(time.Hour)
	out = r.handle(r.event("ev-hb2", "file_open", decoyOpen("x"), "success"))
	if out.Status != policy.Violation || out.Candidate || out.Action != policy.Alert || !contains(out.Blockers, "WORKLOAD_NOT_READY") {
		t.Fatalf("%+v", out)
	}
	if !contains(out.Notes, "sensor heartbeat is stale") {
		t.Fatalf("notes %v", out.Notes)
	}
	if len(r.mock.Calls()) != 0 || r.state(cidWorker) != adapter.Running {
		t.Fatal("a workload whose sensor went silent must not be paused on its say-so")
	}
	// The sensor is talking again: the violating event itself was its heartbeat, so
	// a prompt follow-up is judged healthy and contained.
	r.now = r.now.Add(time.Second)
	out = r.handle(r.event("ev-hb3", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Verified)
}

func TestSensorNeverHeardIsMeasuredFromControllerStart(t *testing.T) {
	// Right after start, a sensor's first event is not stale: it cannot have been
	// silent longer than the controller has listened.
	r := newRig(t, withHeartbeat(10*time.Minute))
	mustState(t, r.handle(r.event("ev-first", "file_open", decoyOpen("x"), "success")), journal.Verified)

	// A controller that has been up for an hour without hearing from the sensor
	// treats its first message as the end of a long silence.
	r2 := newRig(t, withHeartbeat(10*time.Minute))
	r2.now = r2.now.Add(time.Hour)
	out := r2.handle(r2.event("ev-late", "file_open", decoyOpen("x"), "success"))
	if out.Candidate || !contains(out.Blockers, "WORKLOAD_NOT_READY") || !contains(out.Notes, "sensor heartbeat is stale") {
		t.Fatalf("%+v", out)
	}
}

// --- revalidation right before acting -----------------------------------------

func TestContainerReplacedBetweenEvaluateAndActAborts(t *testing.T) {
	r := newRig(t)
	// Inspect #1 is the evaluation; #2 is the refresh before Revalidate. Swap the
	// container in between: same id, new generation (a restart or re-creation).
	r.mock.InspectHook = func(call int) {
		if call == 2 {
			r.mock.Replace(cidWorker, "generation-2")
		}
	}
	out := r.handle(r.event("ev-gen", "file_open", decoyOpen("ev-gen"), "success"))
	if !out.Candidate {
		t.Fatalf("expected a candidate from the first evaluation: %+v", out)
	}
	mustState(t, out, journal.Aborted)
	if len(r.mock.Calls()) != 0 {
		t.Fatal("adapter must not be called after a failed revalidation")
	}
	p, _ := r.api.lastPatch()
	if p.Body.Response["state"] != "aborted" || p.Body.Status != "" {
		t.Fatalf("%+v", p.Body)
	}
}

func TestExpiredCandidateAborts(t *testing.T) {
	r := newRig(t)
	// The controller reads its clock once per phase; advancing it during the
	// evaluation's inspection means the pre-action refresh runs 6 s later.
	r.mock.InspectHook = func(call int) {
		if call == 1 {
			r.now = r.now.Add(6 * time.Second) // past the 5 s action lease
		}
	}
	out := r.handle(r.event("ev-ttl", "file_open", decoyOpen("ev-ttl"), "success"))
	mustState(t, out, journal.Aborted)
	if len(r.mock.Calls()) != 0 {
		t.Fatal("adapter called on an expired lease")
	}
}

// --- engine gates the controller must not bypass --------------------------------

func TestShadowProfileNeverReachesAdapter(t *testing.T) {
	p := activeProfile()
	p.Mode = policy.Shadow
	r := newRig(t, withProfile(p))
	out := r.handle(r.event("ev-shadow", "file_open", decoyOpen("ev-shadow"), "success"))
	if out.Candidate || out.Action != policy.Alert || !contains(out.Blockers, "SHADOW_MODE") {
		t.Fatalf("%+v", out)
	}
	if len(r.mock.Calls()) != 0 {
		t.Fatal("shadow mode must never act")
	}
	if out.IncidentID == "" {
		t.Fatal("shadow violations are still reported as incidents")
	}
}

func TestFailedOutcomeOnlyAlerts(t *testing.T) {
	r := newRig(t)
	out := r.handle(r.event("ev-fail", "file_open", decoyOpen("ev-fail"), "failed"))
	if out.Candidate || !contains(out.Blockers, "OUTCOME_NOT_SUCCESSFUL") {
		t.Fatalf("%+v", out)
	}
}

func TestUnresolvedPathIsNotVerifiedResource(t *testing.T) {
	r := newRig(t)
	tgt := decoyOpen("x")
	tgt.PathResolved = false
	out := r.handle(r.event("ev-sym", "file_open", tgt, "success"))
	if out.Candidate || !contains(out.Blockers, "RESOURCE_NOT_VERIFIED") {
		t.Fatalf("%+v", out)
	}
}

func TestUnauthenticatedChannelIsBlocked(t *testing.T) {
	r := newRig(t)
	env := r.event("ev-anon", "file_open", decoyOpen("ev-anon"), "success")
	env.Authentic = false
	out := r.handle(env)
	if out.Candidate || !contains(out.Blockers, "UNAUTHENTICATED_SENSOR") {
		t.Fatalf("%+v", out)
	}
}

func TestSensorClassIsOverriddenByControllerTable(t *testing.T) {
	r := newRig(t)
	// The sensor claims curl is DIAGNOSTIC (allowed). The controller classifies it
	// NET_CLIENT (denied), so the decision is a violation regardless.
	out := r.handle(r.event("ev-curl", "process_exec", normalize.RawTarget{Exe: "/usr/bin/curl", BinaryClass: "DIAGNOSTIC"}, "success"))
	if out.Status != policy.Violation || out.Decision.Findings[0].Code != "EXEC_CLASS_DENIED" {
		t.Fatalf("%+v", out.Decision)
	}
	if !containsPrefix(out.Notes, "sensor class DIAGNOSTIC overridden") {
		t.Fatalf("notes %v", out.Notes)
	}
}

func TestUnenrolledWorkloadIsNotEvaluated(t *testing.T) {
	r := newRig(t)
	env := r.event("ev-stranger", "file_open", decoyOpen("x"), "success")
	env.Raw.Facts.Workload = normalize.RawWorkload{ID: "stranger-77"}
	out := r.handle(env)
	if !out.Unenrolled || out.Candidate || out.IncidentID != "" {
		t.Fatalf("%+v", out)
	}
}

func TestSharedServiceNeverPaused(t *testing.T) {
	r := newRig(t)
	env := r.event("ev-pay", "file_open", decoyOpen("x"), "success")
	env.Raw.Facts.Workload = normalize.RawWorkload{ID: "payments-01", ContainerID: cidPayments}
	out := r.handle(env)
	if out.Candidate || out.Decision.RecommendedAction != policy.Revoke {
		t.Fatalf("%+v", out.Decision)
	}
	if !contains(out.Blockers, "ADAPTER_UNAVAILABLE") || !contains(out.Blockers, "NO_BOUND_SESSION") {
		t.Fatalf("blockers %v", out.Blockers)
	}
	if len(r.mock.Calls()) != 0 {
		t.Fatal("shared service touched")
	}
}

// --- restart recovery -----------------------------------------------------------

func TestRestartReconcilesInterruptedExecution(t *testing.T) {
	jpath := filepath.Join(t.TempDir(), "j.jsonl")
	r := newRig(t, withJournal(jpath))

	// Simulate a crash after the adapter call went out: the journal says EXECUTING,
	// the runtime says paused, nothing was reported.
	j := r.c.Journal()
	key := "policy_" + repeat("c", 64)
	if _, err := j.Reserve(key, "PAUSE_CONTAINER", cidWorker, "worker-01", "ev-crash"); err != nil {
		t.Fatal(err)
	}
	if err := j.Transition(key, journal.Executing, nil, 0); err != nil {
		t.Fatal(err)
	}
	_ = r.mock.Pause(context.Background(), cidWorker)
	// Pretend the decision had been journaled and the incident created before the crash.
	st := stored{Decision: policy.Decision{EventID: "ev-crash"}, Report: true}
	if _, err := j.RecordDecision("ev-crash", st, true); err != nil {
		t.Fatal(err)
	}
	_ = j.MarkIncidentCreated("ev-crash", "inc_pre")
	r.api.mu.Lock()
	r.api.incidents["inc_pre"] = map[string]any{}
	r.api.mu.Unlock()

	r.restart()

	a, _ := r.c.Journal().Action(key)
	if a.State != journal.Verified || a.Detail["reconciled"] != true {
		t.Fatalf("after restart: %+v", a)
	}
	p, ok := r.api.lastPatch()
	if !ok || p.IncidentID != "inc_pre" || p.Body.Status != "contained" {
		t.Fatalf("reconciled result not reported: %+v %v", p, ok)
	}
}

func TestRestartAbortsReservedButNeverExecuted(t *testing.T) {
	jpath := filepath.Join(t.TempDir(), "j.jsonl")
	r := newRig(t, withJournal(jpath))
	key := "policy_" + repeat("d", 64)
	if _, err := r.c.Journal().Reserve(key, "PAUSE_CONTAINER", cidWorker, "worker-01", "ev-res"); err != nil {
		t.Fatal(err)
	}
	r.restart()
	a, _ := r.c.Journal().Action(key)
	if a.State != journal.Aborted {
		t.Fatalf("%+v", a)
	}
	if r.state(cidWorker) != adapter.Running {
		t.Fatal("reconciliation must never act")
	}
}

func TestJournalSurvivesRestartAndKeepsDuplicateProtection(t *testing.T) {
	jpath := filepath.Join(t.TempDir(), "j.jsonl")
	r := newRig(t, withJournal(jpath))
	env := r.event("ev-persist", "file_open", decoyOpen("x"), "success")
	mustState(t, r.handle(env), journal.Verified)
	r.restart()
	out := r.handle(env)
	if !out.Duplicate || len(r.mock.Calls()) != 1 {
		t.Fatalf("%+v calls=%v", out, r.mock.Calls())
	}
}

// --- outbox -------------------------------------------------------------------------

func TestAPIOutageDoesNotStopContainmentAndIsRetried(t *testing.T) {
	r := newRig(t)
	r.api.setDown(true)
	out := r.handle(r.event("ev-out", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Verified) // contained even though nothing could be reported
	if out.IncidentID != "" || r.api.patchCount() != 0 {
		t.Fatal("nothing should have reached the API")
	}
	if r.c.Journal().Stats().PendingReports != 1 {
		t.Fatalf("stats %+v", r.c.Journal().Stats())
	}
	r.api.setDown(false)
	r.c.Flush(context.Background())
	ev, _ := r.c.Journal().Event("ev-out")
	if ev.IncidentID == "" || !ev.ResponseDone || r.api.patchCount() != 1 {
		t.Fatalf("flush did not complete: %+v", ev)
	}
	r.c.Flush(context.Background())
	if r.api.patchCount() != 1 {
		t.Fatal("flush must be idempotent")
	}
}

func TestEventAlreadyInAPIHistoryIsAttachedById(t *testing.T) {
	// The sensor's own history sink posted the event first (409 on embed): the
	// controller must attach by event_ids, not orphan.
	r := newRig(t)
	r.api.mu.Lock()
	r.api.workloads["worker-01"] = true
	r.api.events["ev-hist"] = "" // stored, not attached to any incident
	r.api.mu.Unlock()
	out := r.handle(r.event("ev-hist", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Verified)
	if out.IncidentID == "" {
		t.Fatal("incident not created by event_ids")
	}
	if p, ok := r.api.lastPatch(); !ok || p.IncidentID != out.IncidentID || p.Body.Status != "contained" {
		t.Fatalf("response not reported on the attached incident: %+v", p)
	}
	if st := r.c.Journal().Stats(); st.Orphaned != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestIncidentAlreadyKnownToAPIIsOrphanedNotRetriedForever(t *testing.T) {
	r := newRig(t)
	// Someone (e.g. the policy-eval reporter) already opened an incident on this event.
	r.api.mu.Lock()
	r.api.workloads["worker-01"] = true
	r.api.events["ev-orph"] = "inc_other"
	r.api.mu.Unlock()
	out := r.handle(r.event("ev-orph", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Verified)
	ev, _ := r.c.Journal().Event("ev-orph")
	if !ev.Orphaned || ev.IncidentID != "" {
		t.Fatalf("%+v", ev)
	}
	if st := r.c.Journal().Stats(); st.Orphaned != 1 || st.PendingReports != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestOfflineModeJournalsWithoutReporting(t *testing.T) {
	r := newRig(t, noAPI())
	out := r.handle(r.event("ev-off", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Verified)
	if r.api.patchCount() != 0 {
		t.Fatal("offline controller reported")
	}
}

// --- helpers ----------------------------------------------------------------------

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsPrefix(list []string, prefix string) bool {
	for _, x := range list {
		if len(x) >= len(prefix) && x[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
