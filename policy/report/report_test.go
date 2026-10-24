package report

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	policy "river3.local/policy"
)

func sampleEvent() policy.Event {
	return policy.Event{
		ID: "fixture-2",
		Identity: policy.Identity{TenantID: "lab", AssetID: "worker-01", HostID: "podman-vm", Generation: "generation-1",
			ContainerID: strings.Repeat("a", 64)},
		ObservedAt: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), Provenance: policy.Simulation,
		Operation: policy.FileOpen, Outcome: policy.Succeeded, Path: "/opt/config/.db_recovery_creds", OpenRead: true,
	}
}

func violation() policy.Decision {
	return policy.Decision{
		EventID: "fixture-2", Outcome: policy.Succeeded, Provenance: policy.Simulation,
		ProfileName: "diagnostic-worker", ProfileVersion: 1, Mode: policy.Shadow, Status: policy.Violation,
		Findings:          []policy.Finding{{Code: "READ_OUTSIDE_SCOPE"}, {Code: "DECOY_OPEN", Rule: "/opt/config/.db_recovery_creds"}},
		RecommendedAction: policy.Pause, Action: policy.Alert, Blockers: []string{"SHADOW_MODE", "NON_LIVE_EVIDENCE"},
	}
}

func TestBuildIncidentMapping(t *testing.T) {
	inc := BuildIncident(sampleEvent(), violation(), "ai_worker")
	if inc.Title != "Decoy file opened" || inc.Rule != "DECOY_OPEN" {
		t.Fatalf("headline should be the decoy finding, got %q / %q", inc.Title, inc.Rule)
	}
	if inc.Severity != "critical" || inc.Verdict != "prohibited" || inc.Threat != "agent_drift" || inc.Mode != "shadow" {
		t.Fatalf("bad mapping: %+v", inc)
	}
	if !inc.Demo {
		t.Fatal("simulation evidence must be flagged demo")
	}
	if inc.Policy.Action != policy.Alert || inc.Policy.RecommendedAction != policy.Pause {
		t.Fatal("decision must be stored as-is")
	}
	if !strings.Contains(inc.Reason, "held at ALERT by: SHADOW_MODE, NON_LIVE_EVIDENCE") {
		t.Fatalf("reason should explain the hold: %q", inc.Reason)
	}
	ev := inc.Events[0]
	if ev.Kind != "file_open" || ev.Outcome != "success" || ev.WorkloadID != "worker-01" {
		t.Fatalf("bad event mapping: %+v", ev)
	}
	tgt := ev.Facts["target"].(map[string]any)
	if tgt["path"] != "/opt/config/.db_recovery_creds" || tgt["access"] != "read" {
		t.Fatalf("bad target: %+v", tgt)
	}
}

func TestOutcomeAndKindMapping(t *testing.T) {
	cases := map[policy.Outcome]string{policy.Succeeded: "success", policy.Failed: "failed",
		policy.Attempted: "pending", policy.UnknownOutcome: "unknown"}
	for in, want := range cases {
		if got := apiOutcome(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	d := violation()
	d.Status, d.Findings = policy.Review, []policy.Finding{{Code: "GUARD_B_WARN_OPERATOR"}}
	inc := BuildIncident(sampleEvent(), d, "shared_service")
	if inc.Verdict != "unresolved" || inc.Severity != "info" || inc.Threat != "external_exploit" {
		t.Fatalf("review mapping wrong: %+v", inc)
	}
}

type capture struct {
	calls  atomic.Int32
	bodies []map[string]any
	auth   []string
}

func server(t *testing.T, c *capture, statuses ...int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(c.calls.Add(1))
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		c.bodies = append(c.bodies, m)
		c.auth = append(c.auth, r.Header.Get("Authorization"))
		st := statuses[len(statuses)-1]
		if n <= len(statuses) {
			st = statuses[n-1]
		}
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"detail":"x"}`))
	}))
}

func newReporter(t *testing.T, url string, unknown bool) *Reporter {
	t.Helper()
	r, err := New(Config{BaseURL: url, Token: "m-policy", ReportUnknown: unknown, Backoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportPostsViolationWithBearer(t *testing.T) {
	c := &capture{}
	s := server(t, c, 201)
	defer s.Close()
	r := newReporter(t, s.URL, false)
	res, err := r.Report(context.Background(), sampleEvent(), violation(), "ai_worker")
	if err != nil || res != Posted {
		t.Fatalf("got %v %v", res, err)
	}
	if c.auth[0] != "Bearer m-policy" || c.bodies[0]["severity"] != "critical" {
		t.Fatalf("bad request: %v %v", c.auth, c.bodies[0])
	}
}

func TestReportSkipsInScopeAndUnknownByDefault(t *testing.T) {
	c := &capture{}
	s := server(t, c, 201)
	defer s.Close()
	r := newReporter(t, s.URL, false)
	d := violation()
	d.Status = policy.InScope
	if res, _ := r.Report(context.Background(), sampleEvent(), d, "ai_worker"); res != SkipScope {
		t.Fatal(res)
	}
	d.Status = policy.Unknown
	if res, _ := r.Report(context.Background(), sampleEvent(), d, "ai_worker"); res != SkipUnknwn {
		t.Fatal(res)
	}
	if c.calls.Load() != 0 {
		t.Fatal("nothing should be posted")
	}
	st := r.Stats()
	if st.SkippedInScope != 1 || st.SkippedUnknown != 1 {
		t.Fatalf("%+v", st)
	}
	// opt-in
	r2 := newReporter(t, s.URL, true)
	if res, _ := r2.Report(context.Background(), sampleEvent(), d, "ai_worker"); res != Posted {
		t.Fatal(res)
	}
}

func TestRetriesTransientThenSucceeds(t *testing.T) {
	c := &capture{}
	s := server(t, c, 503, 429, 201)
	defer s.Close()
	r := newReporter(t, s.URL, false)
	if res, err := r.Report(context.Background(), sampleEvent(), violation(), "ai_worker"); err != nil || res != Posted {
		t.Fatalf("%v %v", res, err)
	}
	if c.calls.Load() != 3 {
		t.Fatalf("calls=%d", c.calls.Load())
	}
}

func TestDuplicateIsSuccessAndClientErrorsDoNotRetry(t *testing.T) {
	c := &capture{}
	s := server(t, c, 409)
	defer s.Close()
	r := newReporter(t, s.URL, false)
	if res, err := r.Report(context.Background(), sampleEvent(), violation(), "ai_worker"); err != nil || res != Duplicate {
		t.Fatalf("%v %v", res, err)
	}
	c2 := &capture{}
	s2 := server(t, c2, 403)
	defer s2.Close()
	r2 := newReporter(t, s2.URL, false)
	_, err := r2.Report(context.Background(), sampleEvent(), violation(), "ai_worker")
	var apiErr *APIError
	if err == nil || !errors.As(err, &apiErr) || apiErr.Status != 403 || c2.calls.Load() != 1 {
		t.Fatalf("403 must fail once without retry: %v calls=%d", err, c2.calls.Load())
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	c := &capture{}
	s := server(t, c, 500)
	defer s.Close()
	r := newReporter(t, s.URL, false)
	if _, err := r.Report(context.Background(), sampleEvent(), violation(), "ai_worker"); err == nil {
		t.Fatal("expected failure")
	}
	if c.calls.Load() != 4 || r.Stats().Failed != 1 {
		t.Fatalf("calls=%d stats=%+v", c.calls.Load(), r.Stats())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hit atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1) }))
	defer evil.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	r := newReporter(t, s.URL, false)
	_, _ = r.Report(context.Background(), sampleEvent(), violation(), "ai_worker")
	if hit.Load() != 0 {
		t.Fatal("token must never follow a redirect")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{BaseURL: "http://river3.example", Token: "t"},      // plain http off-host
		{BaseURL: "https://u:p@river3.example", Token: "t"}, // credentials in URL
		{BaseURL: "https://river3.example", Token: " "},     // no token
		{BaseURL: "ftp://river3.example", Token: "t"},
	}
	for _, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	for _, ok := range []string{"https://river3.example", "http://127.0.0.1:8000", "http://localhost:8000"} {
		if _, err := New(Config{BaseURL: ok, Token: "t"}); err != nil {
			t.Errorf("rejected %s: %v", ok, err)
		}
	}
}
