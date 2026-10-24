package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/guard"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	policy "river3.local/policy"
)

func withGuard(g guard.Guard) rigOpt {
	return func(_ *rig, c *Config) { c.Guard = g }
}

// an in-scope exec with an argv payload, so both channels have something to assess
func (r *rig) benignExecWithPayload(id string) normalize.Envelope {
	env := r.event(id, "process_exec", normalize.RawTarget{Exe: "/usr/bin/cat"}, "success")
	env.Raw.Payload = map[string]any{"argv": []string{"cat", "/var/log/app/error.log"}}
	return env
}

func TestChannelBAloneCannotContain(t *testing.T) {
	// Laya's payload guard screams "contain"; the engine must only alert.
	g := &guard.Mock{A: policy.Continue, B: policy.Contain}
	r := newRig(t, withGuard(g))
	out := r.handle(r.benignExecWithPayload("ev-b"))
	if out.Status != policy.Review || out.Action != policy.Alert || out.Candidate {
		t.Fatalf("%+v", out)
	}
	if len(r.mock.Calls()) != 0 {
		t.Fatal("payload-only verdict reached the adapter")
	}
	if out.Decision.Findings[0].Code != "GUARD_B_REQUEST_CONTAINMENT" {
		t.Fatalf("%+v", out.Decision.Findings)
	}
	if g.Calls != 1 {
		t.Fatal(g.Calls)
	}
}

func TestChannelAContainNeedsProfileOptIn(t *testing.T) {
	g := &guard.Mock{A: policy.Contain}
	// default fixture profile: on_structural_guard = ALERT
	r := newRig(t, withGuard(g))
	out := r.handle(r.benignExecWithPayload("ev-a1"))
	if out.Status != policy.Review || out.Decision.RecommendedAction != policy.Alert || out.Candidate {
		t.Fatalf("%+v", out.Decision)
	}

	// profile opts in: a verified Channel A containment request on a live, successful,
	// dedicated worker becomes a candidate and is executed like any other.
	p := activeProfile()
	p.Response.OnStructuralGuard = policy.Pause
	r2 := newRig(t, withGuard(&guard.Mock{A: policy.Contain}), withProfile(p))
	out = r2.handle(r2.benignExecWithPayload("ev-a2"))
	if !out.Candidate || out.Decision.RecommendedAction != policy.Pause {
		t.Fatalf("%+v", out.Decision)
	}
	mustState(t, out, journal.Verified)
}

func TestUnverifiedAssessmentIsUntrusted(t *testing.T) {
	g := &guard.Mock{A: policy.Contain, Unverified: true}
	p := activeProfile()
	p.Response.OnStructuralGuard = policy.Pause
	r := newRig(t, withGuard(g), withProfile(p))
	out := r.handle(r.benignExecWithPayload("ev-u"))
	if out.Candidate || !hasFinding(out.Decision, "UNTRUSTED_GUARD_ASSESSMENT") {
		t.Fatalf("%+v", out.Decision)
	}
}

func TestGuardUnavailableDoesNotEraseDeterministicFinding(t *testing.T) {
	g := &guard.Mock{A: policy.Unavailable}
	r := newRig(t, withGuard(g))
	out := r.handle(r.event("ev-g", "file_open", decoyOpen("x"), "success"))
	// decoy open is deterministic: a violation, paused, and the (down) guard was
	// never even asked — its outage cannot turn the decision UNKNOWN.
	if out.Status != policy.Violation || !hasFinding(out.Decision, "DECOY_OPEN") || hasFinding(out.Decision, "GUARD_UNAVAILABLE") {
		t.Fatalf("%+v", out.Decision)
	}
	mustState(t, out, journal.Verified)
	if g.Calls != 0 {
		t.Fatalf("guard consulted %d times on a deterministic violation", g.Calls)
	}
	// ...but a benign event with the guard down is UNKNOWN, not silently IN_SCOPE
	out = r.handle(r.event("ev-g2", "file_open", normalize.RawTarget{Path: "/var/log/app/error.log", PathResolved: true, Access: "read"}, "success"))
	if out.Status != policy.Unknown || !hasFinding(out.Decision, "GUARD_UNAVAILABLE") || g.Calls != 1 {
		t.Fatalf("%+v calls=%d", out.Decision, g.Calls)
	}
}

// slowGuard wraps the mock with a delay and a hook, standing in for a model that
// takes seconds per call.
type slowGuard struct {
	guard.Mock
	sleep    time.Duration
	onAssess func()
}

func (s *slowGuard) Assess(ctx context.Context, in guard.Input) []policy.Assessment {
	time.Sleep(s.sleep)
	if s.onAssess != nil {
		s.onAssess()
	}
	return s.Mock.Assess(ctx, in)
}

func TestDeterministicViolationNeverWaitsOnTheGuard(t *testing.T) {
	g := &slowGuard{Mock: guard.Mock{A: policy.Warn, B: policy.Continue}, sleep: 300 * time.Millisecond}
	r := newRig(t, withGuard(g))

	start := time.Now()
	out := r.handle(r.event("ev-fast", "file_open", decoyOpen("x"), "success"))
	elapsed := time.Since(start)
	if out.Status != policy.Violation || !out.Candidate {
		t.Fatalf("%+v", out.Decision)
	}
	mustState(t, out, journal.Verified)
	if g.Calls != 0 {
		t.Fatalf("guard called %d times for a deterministic violation", g.Calls)
	}
	if elapsed >= g.sleep {
		t.Fatalf("containment took %s: it waited on the model", elapsed)
	}
	// The incident says the guard was not consulted, rather than showing no verdicts
	// as if the guard were off.
	r.api.mu.Lock()
	inc := r.api.incidents[out.IncidentID]
	r.api.mu.Unlock()
	gf := inc["events"].([]any)[0].(map[string]any)["facts"].(map[string]any)["guard"].(map[string]any)
	if gf["consulted"] != false || gf["name"] != "mock-guard" {
		t.Fatalf("%+v", gf)
	}

	// A benign event is where the guard earns its keep: it is consulted and its
	// verdict (WARN) lifts the event to REVIEW with the assessment on the incident.
	// (The worker is paused now, so this is a second, un-paused workload's event.)
	r.mock.Add(cidWorker, "generation-1", adapter.Running)
	out = r.handle(r.benignExecWithPayload("ev-benign"))
	if out.Status != policy.Review || !hasFinding(out.Decision, "GUARD_A_WARN_OPERATOR") || g.Calls != 1 {
		t.Fatalf("%+v calls=%d", out.Decision, g.Calls)
	}
	r.api.mu.Lock()
	inc = r.api.incidents[out.IncidentID]
	r.api.mu.Unlock()
	gf = inc["events"].([]any)[0].(map[string]any)["facts"].(map[string]any)["guard"].(map[string]any)
	if gf["consulted"] != true || len(gf["assessments"].([]any)) != 2 {
		t.Fatalf("%+v", gf)
	}
}

func TestCandidateLeaseStartsAfterTheGuardAnswers(t *testing.T) {
	// Two sequential model calls can take longer than the 5 s candidate lease. The
	// lease must run from the moment the engine decides (after the guard), not from
	// the moment the event arrived; otherwise every post-guard candidate is already
	// expired when Revalidate looks at it.
	p := activeProfile()
	p.Response.OnStructuralGuard = policy.Pause
	var r *rig
	g := &slowGuard{Mock: guard.Mock{A: policy.Contain}}
	g.onAssess = func() { r.now = r.now.Add(16 * time.Second) } // 2 × an 8 s model timeout
	r = newRig(t, withGuard(g), withProfile(p))

	out := r.handle(r.benignExecWithPayload("ev-lease"))
	if !out.Candidate || out.Decision.RecommendedAction != policy.Pause {
		t.Fatalf("%+v", out.Decision)
	}
	mustState(t, out, journal.Verified)
	if out.Decision.Candidate.IssuedAt != r.now {
		t.Fatalf("lease issued at %s, engine decided at %s", out.Decision.Candidate.IssuedAt, r.now)
	}
	if contains(out.Blockers, "STALE_EVENT") {
		t.Fatalf("a 16 s old event is within the 30 s freshness bound: %v", out.Blockers)
	}

	// The event's own age is still measured honestly: a guard that takes longer than
	// the engine's MaxEventAge (30 s) leaves an event too old to act on.
	g.onAssess = func() { r.now = r.now.Add(31 * time.Second) }
	r.mock.Add(cidWorker, "generation-1", adapter.Running)
	out = r.handle(r.benignExecWithPayload("ev-lease-stale"))
	if out.Candidate || !contains(out.Blockers, "STALE_EVENT") {
		t.Fatalf("%+v", out)
	}
}

func TestGuardVerdictsAreRecordedOnTheIncident(t *testing.T) {
	g := &guard.Mock{A: policy.Warn, B: policy.Continue}
	r := newRig(t, withGuard(g))
	out := r.handle(r.benignExecWithPayload("ev-rec"))
	if out.IncidentID == "" {
		t.Fatal("REVIEW must be reported")
	}
	r.api.mu.Lock()
	inc := r.api.incidents[out.IncidentID]
	r.api.mu.Unlock()
	facts := inc["events"].([]any)[0].(map[string]any)["facts"].(map[string]any)
	gf, ok := facts["guard"].(map[string]any)
	if !ok || gf["name"] != "mock-guard" || len(gf["assessments"].([]any)) != 2 {
		t.Fatalf("%+v", facts["guard"])
	}
}

// fakeLayaServe is a minimal laya-serve: POST /v1/systemone answering the one
// "verdict" question with the scripted option and confidence. It records the state
// of every call so the test can see what the model was shown.
type fakeLayaServe struct {
	srv        *httptest.Server
	mu         sync.Mutex
	option     string
	confidence float64
	states     []map[string]any
}

func newFakeLayaServe(t *testing.T, option string, confidence float64) *fakeLayaServe {
	t.Helper()
	f := &fakeLayaServe{option: option, confidence: confidence}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/systemone" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			State     map[string]any            `json:"state"`
			Questions map[string]map[string]any `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Questions) != 1 {
			http.Error(w, "bad body", http.StatusUnprocessableEntity)
			return
		}
		f.mu.Lock()
		f.states = append(f.states, body.State)
		opt, conf := f.option, f.confidence
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "laya-421m-english",
			"answers": map[string]any{"verdict": map[string]any{"type": "choice", "choice": opt,
				"probabilities": map[string]float64{opt: conf}, "confidence": conf}},
			"usage": map[string]any{"tokens": 1},
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLayaServe) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.states)
}

func (f *fakeLayaServe) script(option string, confidence float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.option, f.confidence = option, confidence
}

func TestLayaEndToEnd(t *testing.T) {
	f := newFakeLayaServe(t, "CONTINUE", 0.93)
	l, err := guard.NewLaya(guard.LayaConfig{BaseURL: f.srv.URL, ChannelA: true, ChannelB: true, MinConfidence: 0.6})
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, withGuard(l))

	// A decoy read is a deterministic VIOLATION: paused and verified without laya-serve
	// ever being asked.
	out := r.handle(r.event("ev-decoy", "file_open", decoyOpen("x"), "success"))
	if out.Status != policy.Violation || !out.Candidate || !hasFinding(out.Decision, "DECOY_OPEN") {
		t.Fatalf("%+v", out.Decision)
	}
	mustState(t, out, journal.Verified)
	if f.calls() != 0 {
		t.Fatalf("laya-serve called %d times for a deterministic violation", f.calls())
	}

	// A benign exec with a payload: both channels are asked, both come back as a
	// confident CONTINUE, both are verified, and the event stays IN_SCOPE with no
	// guard finding and nothing reported.
	r.mock.Add(cidWorker, "generation-1", adapter.Running)
	out = r.handle(r.benignExecWithPayload("ev-benign"))
	if out.Status != policy.InScope || out.Candidate || out.IncidentID != "" {
		t.Fatalf("%+v", out)
	}
	for _, code := range []string{"UNTRUSTED_GUARD_ASSESSMENT", "GUARD_UNAVAILABLE", "GUARD_A_CONTINUE", "GUARD_B_CONTINUE"} {
		if hasFinding(out.Decision, code) {
			t.Fatalf("unexpected finding %s: %+v", code, out.Decision.Findings)
		}
	}
	if f.calls() != 2 {
		t.Fatalf("%d systemone calls, want 2 (A and B)", f.calls())
	}
	if l.Name() != "laya:laya-421m-english" {
		t.Fatalf("model not recorded: %q", l.Name())
	}
	// what the model saw: A had the profile and facts and no argv; B had only the text
	f.mu.Lock()
	stateA, stateB := f.states[0], f.states[1]
	f.mu.Unlock()
	if stateA["profile"] != "diagnostic-worker" || stateA["facts"] == nil {
		t.Fatalf("A state %+v", stateA)
	}
	rawA, _ := json.Marshal(stateA)
	if strings.Contains(string(rawA), "argv") || strings.Contains(string(rawA), "error.log") {
		t.Fatalf("payload in Channel A state: %s", rawA)
	}
	if len(stateB) != 1 || !strings.Contains(stateB["untrusted_text"].(string), "error.log") {
		t.Fatalf("B state %+v", stateB)
	}

	// The same benign event with an under-confident answer is UNKNOWN (untrusted
	// assessment), never IN_SCOPE by default.
	f.script("CONTINUE", 0.4)
	out = r.handle(r.benignExecWithPayload("ev-unsure"))
	if out.Status != policy.Unknown || !hasFinding(out.Decision, "UNTRUSTED_GUARD_ASSESSMENT") {
		t.Fatalf("%+v", out.Decision)
	}

	// A confident WARN on Channel A lifts the event to REVIEW, and the incident
	// records the laya model name.
	f.script("WARN_OPERATOR", 0.88)
	out = r.handle(r.benignExecWithPayload("ev-warn"))
	if out.Status != policy.Review || !hasFinding(out.Decision, "GUARD_A_WARN_OPERATOR") || out.Candidate {
		t.Fatalf("%+v", out.Decision)
	}
	r.api.mu.Lock()
	inc := r.api.incidents[out.IncidentID]
	r.api.mu.Unlock()
	gf := inc["events"].([]any)[0].(map[string]any)["facts"].(map[string]any)["guard"].(map[string]any)
	if gf["name"] != "laya:laya-421m-english" || gf["consulted"] != true || len(gf["assessments"].([]any)) != 2 {
		t.Fatalf("%+v", gf)
	}
}

func hasFinding(d policy.Decision, code string) bool {
	for _, f := range d.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
