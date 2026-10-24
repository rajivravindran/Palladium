package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

const (
	cidWorker   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cidPayments = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sensorToken = "dev-sensor-token"
)

// fakeAPI is the subset of the River3 API the controller talks to, with the
// same status codes the real one returns.
type fakeAPI struct {
	mu         sync.Mutex
	srv        *httptest.Server
	down       bool
	workloads  map[string]bool
	events     map[string]string // event id -> incident id
	incidents  map[string]map[string]any
	patches    []patch
	queue      []apiclient.OperatorAction
	results    map[string]apiclient.ActionResult
	nextInc    int
	posts      int // every POST /api/v1/incidents, including the ones answered 409
	bundle     apiclient.PolicyBundle
	reports    []apiclient.PolicyReport
	sessions   []apiclient.Session // GET /api/v1/sessions, all states; the handler filters
	sessionQs  []string            // raw query strings the controller sent
	registered []map[string]any    // every POST /api/v1/workloads body
}

type patch struct {
	IncidentID string
	Body       apiclient.ResponseUpdate
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{workloads: map[string]bool{}, events: map[string]string{}, incidents: map[string]map[string]any{}, results: map[string]apiclient.ActionResult{}}
	mux := http.NewServeMux()
	auth := func(role string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			down := f.down
			f.mu.Unlock()
			if down {
				http.Error(w, `{"detail":"down"}`, 503)
				return
			}
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tok != "m-"+role {
				http.Error(w, `{"detail":"forbidden"}`, 403)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /api/v1/workloads", auth("policy", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.workloads[body["id"].(string)] = true
		f.registered = append(f.registered, body)
		f.mu.Unlock()
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(body)
	}))
	mux.HandleFunc("POST /api/v1/incidents", auth("policy", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.posts++
		if !f.workloads[body["workload_id"].(string)] {
			http.Error(w, `{"detail":"unknown workload; enroll it first"}`, 422)
			return
		}
		var eid string
		if evs, ok := body["events"].([]any); ok && len(evs) > 0 {
			eid = evs[0].(map[string]any)["id"].(string)
			if _, dup := f.events[eid]; dup {
				http.Error(w, fmt.Sprintf(`{"detail":"duplicate event id %s"}`, eid), 409)
				return
			}
		} else if ids, ok := body["event_ids"].([]any); ok && len(ids) > 0 {
			eid = ids[0].(string)
			owner, known := f.events[eid]
			if !known {
				http.Error(w, fmt.Sprintf(`{"detail":"unknown event id %s"}`, eid), 422)
				return
			}
			if owner != "" {
				http.Error(w, fmt.Sprintf(`{"detail":"event %s already belongs to %s"}`, eid, owner), 409)
				return
			}
		}
		f.nextInc++
		id := fmt.Sprintf("inc_%06d", f.nextInc)
		f.events[eid] = id
		body["id"] = id
		f.incidents[id] = body
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(body)
	}))
	mux.HandleFunc("PATCH /api/v1/incidents/{id}/response", auth("contain", func(w http.ResponseWriter, r *http.Request) {
		var body apiclient.ResponseUpdate
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		if _, ok := f.incidents[id]; !ok {
			http.Error(w, `{"detail":"incident not found"}`, 404)
			return
		}
		f.patches = append(f.patches, patch{id, body})
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	mux.HandleFunc("GET /api/v1/policy/bundle", auth("policy", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.bundle)
	}))
	mux.HandleFunc("POST /api/v1/policy/sync", auth("policy", func(w http.ResponseWriter, r *http.Request) {
		var body apiclient.PolicyReport
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.reports = append(f.reports, body)
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	mux.HandleFunc("GET /api/v1/sessions", auth("contain", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sessionQs = append(f.sessionQs, r.URL.RawQuery)
		state := r.URL.Query().Get("state")
		out := []apiclient.Session{}
		for _, s := range f.sessions {
			if state == "" || s.State == state {
				out = append(out, s)
			}
		}
		// The real API orders started_at desc and pages; the controller must not depend on
		// the order, so hand them back as stored.
		_ = json.NewEncoder(w).Encode(out)
	}))
	mux.HandleFunc("GET /api/v1/actions", auth("contain", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []apiclient.OperatorAction{}
		for _, a := range f.queue {
			if a.Status == r.URL.Query().Get("status") {
				out = append(out, a)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	mux.HandleFunc("POST /api/v1/actions/{id}/result", auth("contain", func(w http.ResponseWriter, r *http.Request) {
		var body apiclient.ActionResult
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		if _, done := f.results[id]; done {
			http.Error(w, `{"detail":"action already completed"}`, 409)
			return
		}
		f.results[id] = body
		for i := range f.queue {
			if f.queue[i].ID == id {
				f.queue[i].Status = body.Status
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) setDown(d bool) {
	f.mu.Lock()
	f.down = d
	f.mu.Unlock()
}

func (f *fakeAPI) enqueue(a apiclient.OperatorAction) {
	f.mu.Lock()
	f.queue = append(f.queue, a)
	f.mu.Unlock()
}

// setSessions replaces what GET /api/v1/sessions returns.
func (f *fakeAPI) setSessions(s ...apiclient.Session) {
	f.mu.Lock()
	f.sessions = s
	f.mu.Unlock()
}

func activeSession(id, workload, principal, startedAt string) apiclient.Session {
	return apiclient.Session{ID: id, WorkloadID: workload, Principal: principal, State: "active", StartedAt: startedAt}
}

func (f *fakeAPI) lastPatch() (patch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.patches) == 0 {
		return patch{}, false
	}
	return f.patches[len(f.patches)-1], true
}

func (f *fakeAPI) patchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.patches)
}

func (f *fakeAPI) result(id string) (apiclient.ActionResult, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.results[id]
	return r, ok
}

// rig is one controller under test with every collaborator reachable.
type rig struct {
	t       *testing.T
	api     *fakeAPI
	mock    *adapter.Mock
	jpath   string
	c       *Controller
	now     time.Time
	profile policy.Profile
	shared  *policy.Profile // nil = sharedProfile()
	reg     *registry.Registry
	cfg     Config // as built, so restart() keeps the same adapters
}

func activeProfile() policy.Profile {
	return policy.Profile{Name: "diagnostic-worker", Kind: "ai_worker", Version: 1, Mode: policy.Active,
		Decoys: []string{"/opt/config/.db_recovery_creds"}, ProtectRead: []string{"/root/.aws/**", "/etc/shadow"},
		ReadAllow: []string{"/var/log/app/**", "/etc/app/**"}, WriteAllow: []string{"/tmp/diagnostic-output/**"},
		ExecAllow: []string{"DIAGNOSTIC"}, ExecDeny: []string{"NET_CLIENT", "PRIVILEGED_TOOL"}, EgressAllow: []string{},
		Response: policy.ResponsePolicy{OnViolation: policy.Pause, OnStructuralGuard: policy.Alert}}
}

func sharedProfile() policy.Profile {
	return policy.Profile{Name: "payment-service", Kind: "shared_service", Version: 1, Mode: policy.Active,
		Decoys: []string{"/opt/config/.db_recovery_creds"}, ReadAllow: []string{"/etc/app/**"}, WriteAllow: []string{},
		ExecAllow: []string{"OTHER"}, EgressAllow: []string{"10.20.0.0/16"},
		Response: policy.ResponsePolicy{OnViolation: policy.Revoke, OnStructuralGuard: policy.Alert}}
}

func fixtureRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	reg, err := registry.Load(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

type rigOpt func(*rig, *Config)

func withProfile(p policy.Profile) rigOpt {
	return func(r *rig, _ *Config) { r.profile = p }
}

func withJournal(path string) rigOpt {
	return func(r *rig, _ *Config) { r.jpath = path }
}

func noAPI() rigOpt {
	return func(_ *rig, c *Config) { c.API = nil }
}

// withAdapter replaces the mock runtime (live tests).
func withAdapter(a adapter.Adapter) rigOpt {
	return func(_ *rig, c *Config) { c.Adapter = a }
}

// withRegistry starts from a different enrollment snapshot than the fixture file.
func withRegistry(reg *registry.Registry) rigOpt {
	return func(r *rig, c *Config) { r.reg = reg; c.Registry = registry.NewHolder(reg) }
}

// withSessions configures a session adapter (CONTRACTS.md §2.1).
func withSessions(s adapter.SessionAdapter) rigOpt {
	return func(_ *rig, c *Config) { c.Sessions = s }
}

// withEgress turns domain egress on with the given resolver (§5).
func withEgress(e *Egress) rigOpt {
	return func(_ *rig, c *Config) { c.Egress = e }
}

// withSharedProfile replaces the payment-service profile the rig compiles alongside.
func withSharedProfile(p policy.Profile) rigOpt {
	return func(r *rig, _ *Config) { r.shared = &p }
}

// revokeRegistry is the fixture registry with payments-01 permitted to REVOKE_SESSION
// (the administrator's statement that this shared service's sessions may be cut off).
func revokeRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	f, err := registry.LoadFile(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Workloads {
		if f.Workloads[i].AssetID == "payments-01" {
			f.Workloads[i].PermittedActions = []policy.Action{policy.Revoke}
		}
	}
	reg, err := registry.New(f)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// paymentsEvent builds an authenticated, live envelope for the shared service payments-01.
func (r *rig) paymentsEvent(id, kind string, target normalize.RawTarget, outcome string) normalize.Envelope {
	env := r.event(id, kind, target, outcome)
	env.Raw.Facts.Workload = normalize.RawWorkload{ID: "payments-01", ContainerID: cidPayments}
	return env
}

func (f *fakeAPI) incidentPosts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts
}

func (f *fakeAPI) incident(id string) (map[string]any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inc, ok := f.incidents[id]
	return inc, ok
}

func newRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	r := &rig{t: t, api: newFakeAPI(t), mock: adapter.NewMock(), now: time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC),
		profile: activeProfile(), reg: fixtureRegistry(t)}
	r.mock.Add(cidWorker, "generation-1", adapter.Running)
	r.mock.Add(cidPayments, "generation-1", adapter.Running)
	api, err := apiclient.New(apiclient.Config{BaseURL: r.api.srv.URL, ContainmentToken: "m-contain", PolicyToken: "m-policy",
		MaxAttempts: 1, Backoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{API: api, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: func() time.Time { return r.now }}
	for _, o := range opts {
		o(r, &cfg)
	}
	if r.jpath == "" {
		r.jpath = filepath.Join(t.TempDir(), "journal.jsonl")
	}
	r.c = r.build(cfg)
	return r
}

func (r *rig) build(cfg Config) *Controller {
	r.t.Helper()
	shared := sharedProfile()
	if r.shared != nil {
		shared = *r.shared
	}
	profiles := []policy.Profile{r.profile, shared}
	eng, err := policy.NewEngine(profiles, policy.Options{})
	if err != nil {
		r.t.Fatal(err)
	}
	cfg.Engine = eng
	cfg.Profiles = map[string]*policy.Profile{}
	for i := range profiles {
		cfg.Profiles[profiles[i].Name] = &profiles[i]
	}
	if cfg.Registry == nil {
		cfg.Registry = registry.NewHolder(r.reg)
	}
	if cfg.Adapter == nil {
		cfg.Adapter = r.mock
	}
	jr, err := journal.Open(r.jpath)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { jr.Close() })
	cfg.Journal = jr
	r.cfg = cfg
	c, err := New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	return c
}

// restart reopens the same journal in a new controller (simulating a process restart),
// keeping the same runtime, session adapter and egress resolver.
func (r *rig) restart() {
	api, _ := apiclient.New(apiclient.Config{BaseURL: r.api.srv.URL, ContainmentToken: "m-contain", PolicyToken: "m-policy",
		MaxAttempts: 1, Backoff: time.Millisecond})
	r.c = r.build(Config{API: api, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: func() time.Time { return r.now },
		Sessions: r.cfg.Sessions, Egress: r.cfg.Egress, Adapter: r.cfg.Adapter})
}

func (r *rig) sensor() registry.Sensor {
	s, ok := r.reg.Authenticate(sensorToken)
	if !ok {
		r.t.Fatal("fixture sensor token does not match registry")
	}
	return s
}

// event builds an authenticated, live envelope for worker-01.
func (r *rig) event(id, kind string, target normalize.RawTarget, outcome string) normalize.Envelope {
	return normalize.Envelope{
		Raw: normalize.Raw{Facts: normalize.RawFacts{ID: id, Sensor: "lab-sensor", Kind: kind, Outcome: outcome,
			Workload: normalize.RawWorkload{ID: "worker-01", ContainerID: cidWorker},
			Process:  normalize.RawProcess{PID: 4242, Comm: "python3"}, Target: target}},
		Sensor: r.sensor(), Authentic: true, ReceivedAt: r.now, Provenance: policy.Live,
	}
}

func decoyOpen(id string) normalize.RawTarget {
	_ = id
	return normalize.RawTarget{Path: "/opt/config/.db_recovery_creds", PathResolved: true, Access: "read"}
}

func (r *rig) handle(env normalize.Envelope) Outcome {
	r.t.Helper()
	out, err := r.c.HandleEvent(context.Background(), env)
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *rig) state(cid string) adapter.Status {
	info, err := r.mock.Inspect(context.Background(), cid)
	if err != nil {
		r.t.Fatal(err)
	}
	return info.Status
}

func mustState(t *testing.T, out Outcome, want journal.State) {
	t.Helper()
	if out.Response == nil {
		t.Fatalf("no response state; outcome %+v", out)
	}
	if *out.Response != want {
		t.Fatalf("response state %s, want %s (%+v)", *out.Response, want, out)
	}
}
