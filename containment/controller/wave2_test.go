package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/apiclient"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	"river3.local/containment/sign"
	policy "river3.local/policy"
)

// --- fake customer gateway (CONTRACTS.md §2.1) --------------------------------------

const gatewaySecret = "wave2-gateway-secret-0123456789abcdef0123456789"

// fakeGateway verifies the controller's signature with the webhook scheme and keeps
// session state. It is reached through the real adapter.Gateway, so the request and
// reply JSON on the wire are exactly what a customer gateway sees.
type fakeGateway struct {
	mu       sync.Mutex
	srv      *httptest.Server
	sessions map[string]string // id -> state
	revokes  []map[string]any  // bodies received, with "_id" (path) added
	rejected int
	lies     bool // answer "revoked" without changing state
	forget   bool // revoke, then forget the id (404 on the follow-up GET)
	down     bool // every call 503
}

func newGateway(t *testing.T) (*fakeGateway, *adapter.Gateway) {
	t.Helper()
	g := &fakeGateway{sessions: map[string]string{}}
	mux := http.NewServeMux()
	check := func(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte(gatewaySecret))
		mac.Write(sign.Base(r.Header.Get("X-River3-Timestamp"), r.Header.Get("X-River3-Delivery"), body))
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.Header.Get("X-River3-Delivery") == "" || r.Header.Get("X-River3-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			g.rejected++
			http.Error(w, `{"detail":"bad signature"}`, 401)
			return nil, false
		}
		if g.down {
			http.Error(w, `{"detail":"down"}`, 503)
			return nil, false
		}
		return body, true
	}
	mux.HandleFunc("POST /v1/sessions/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		body, ok := check(w, r)
		if !ok {
			return
		}
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		g.mu.Lock()
		defer g.mu.Unlock()
		id := r.PathValue("id")
		if _, known := g.sessions[id]; !known {
			http.Error(w, `{"detail":"no such session"}`, 404)
			return
		}
		req["_id"] = id
		g.revokes = append(g.revokes, req)
		switch {
		case g.forget:
			delete(g.sessions, id)
		case !g.lies:
			g.sessions[id] = "revoked"
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"state":"revoked"}`))
	})
	mux.HandleFunc("GET /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := check(w, r); !ok {
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		st, known := g.sessions[r.PathValue("id")]
		if !known {
			http.Error(w, `{"detail":"no such session"}`, 404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"state": st, "principal": "svc-payments@prod", "started_at": "2026-10-22T08:00:00Z"})
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	gw, err := adapter.NewGateway(g.srv.URL, []byte(gatewaySecret))
	if err != nil {
		t.Fatal(err)
	}
	return g, gw
}

func (g *fakeGateway) bind(id, state string) {
	g.mu.Lock()
	g.sessions[id] = state
	g.mu.Unlock()
}

func (g *fakeGateway) state(id string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessions[id]
}

func (g *fakeGateway) revokeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.revokes)
}

func syncSessions(t *testing.T, r *rig) {
	t.Helper()
	if err := r.c.SyncSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// --- §1.4 sessions from the API ------------------------------------------------------

func TestSessionSyncBindsNewestActiveAndDropsEnded(t *testing.T) {
	r := newRig(t)
	if n := r.c.SessionCounts(); n["synced"] != false || n["bound_workloads"] != 0 {
		t.Fatalf("before sync: %v", n)
	}
	r.api.setSessions(
		activeSession("sess-old", "payments-01", "svc-a", "2026-10-22T07:00:00Z"),
		activeSession("sess-new", "payments-01", "svc-b", "2026-10-22T08:30:00Z"),
		activeSession("sess-w", "worker-01", "agent-7", "2026-10-22T08:00:00Z"),
		apiclient.Session{ID: "sess-ended", WorkloadID: "worker-01", State: "ended", StartedAt: "2026-10-22T09:00:00Z"},
		activeSession("bad id!", "payments-01", "x", "2026-10-22T10:00:00Z"), // the engine would refuse it
	)
	syncSessions(t, r)
	if got := r.c.boundSession("payments-01"); got != "sess-new" {
		t.Fatalf("payments bound to %q, want the newest active", got)
	}
	if got := r.c.boundSession("worker-01"); got != "sess-w" {
		t.Fatalf("worker bound to %q", got)
	}
	n := r.c.SessionCounts()
	if n["synced"] != true || n["bound_workloads"] != 2 || n["active"] != 4 {
		t.Fatalf("counts %v", n)
	}
	r.api.mu.Lock()
	q := r.api.sessionQs[0]
	r.api.mu.Unlock()
	if !strings.Contains(q, "state=active") {
		t.Fatalf("query %q must ask for active sessions only", q)
	}

	// The normalizer stamps the session on the identity: for the shared service and
	// for the AI worker alike. The event itself never carries one.
	env := r.paymentsEvent("ev-s1", "file_open", normalize.RawTarget{Path: "/etc/app/x", PathResolved: true, Access: "read"}, "success")
	out := r.handle(env)
	if out.Status != policy.InScope || out.Decision.EventID != "ev-s1" {
		t.Fatalf("%+v", out)
	}
	res, err := r.c.norm.Normalize(context.Background(), env, r.now)
	if err != nil || res.Context.Identity.SessionID != "sess-new" || res.Event.Identity.SessionID != "sess-new" {
		t.Fatalf("session not stamped: %+v %v", res.Context.Identity, err)
	}
	wres, _ := r.c.norm.Normalize(context.Background(), r.event("ev-s2", "file_open", normalize.RawTarget{Path: "/etc/app/x", PathResolved: true, Access: "read"}, "success"), r.now)
	if wres.Context.Identity.SessionID != "sess-w" {
		t.Fatalf("worker session not stamped: %+v", wres.Context.Identity)
	}

	// The session is revoked at the API: the next sync drops it, and the identity is
	// back to having none.
	r.api.setSessions(activeSession("sess-w", "worker-01", "agent-7", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)
	if got := r.c.boundSession("payments-01"); got != "" {
		t.Fatalf("revoked session still bound: %q", got)
	}
	res, _ = r.c.norm.Normalize(context.Background(), env, r.now)
	if res.Context.Identity.SessionID != "" {
		t.Fatalf("stale session on identity: %+v", res.Context.Identity)
	}
	// An API outage keeps the last map rather than un-binding everything.
	r.api.setDown(true)
	if err := r.c.SyncSessions(context.Background()); err == nil {
		t.Fatal("outage not reported")
	}
	if got := r.c.boundSession("worker-01"); got != "sess-w" {
		t.Fatalf("outage dropped the map: %q", got)
	}
}

// --- §2.3 automatic revoke -------------------------------------------------------------

func activeShared() policy.Profile {
	p := sharedProfile()
	p.Mode = policy.Active
	return p
}

func TestSharedServiceDecoyOpenRevokesSessionVerifiesAndReports(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-pay-1", "active")
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(gw))
	r.api.setSessions(activeSession("sess-pay-1", "payments-01", "svc-payments@prod", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)

	out := r.handle(r.paymentsEvent("ev-rev-1", "file_open", decoyOpen("x"), "success"))
	if out.Status != policy.Violation || out.Action != policy.Revoke || !out.Candidate {
		t.Fatalf("%+v blockers=%v", out, out.Blockers)
	}
	mustState(t, out, journal.Verified)
	if g.state("sess-pay-1") != "revoked" {
		t.Fatalf("gateway session is %s", g.state("sess-pay-1"))
	}
	if len(r.mock.Calls()) != 0 {
		t.Fatalf("the container must not be touched for a revoke: %v", r.mock.Calls())
	}
	if r.state(cidPayments) != adapter.Running {
		t.Fatal("shared service container changed state")
	}

	// What went over the wire to the gateway.
	g.mu.Lock()
	req := g.revokes[0]
	g.mu.Unlock()
	if req["_id"] != "sess-pay-1" || req["idempotency_key"] != out.Key || req["incident_id"] != "ev-rev-1" {
		t.Fatalf("gateway request %v", req)
	}
	if reason, _ := req["reason"].(string); !strings.Contains(reason, "payment-service") || !strings.Contains(reason, "DECOY") {
		t.Fatalf("reason %q", reason)
	}
	if g.rejected != 0 {
		t.Fatalf("%d requests failed the gateway's signature check", g.rejected)
	}

	// The response report (§2.3): action REVOKE_SESSION, state verified, session_id.
	p, ok := r.api.lastPatch()
	if !ok {
		t.Fatal("no response patched")
	}
	resp := p.Body.Response
	if resp["action"] != "REVOKE_SESSION" || resp["state"] != "verified" || resp["session_id"] != "sess-pay-1" || resp["adapter"] != "gateway" {
		t.Fatalf("response %v", resp)
	}
	if resp["session_state"] != "revoked" || resp["principal"] != "svc-payments@prod" || resp["idempotency_key"] != out.Key {
		t.Fatalf("response evidence %v", resp)
	}
	if p.Body.Status != "contained" || p.Body.WorkloadState != "" {
		t.Fatalf("a revoke contains the incident but never freezes the workload: %+v", p.Body)
	}
	// The incident names the session in its facts (candidate target).
	inc, _ := r.api.incident(out.IncidentID)
	if inc == nil {
		t.Fatal("incident not posted")
	}
	// Replay: duplicate, no second revoke.
	dup := r.handle(r.paymentsEvent("ev-rev-1", "file_open", decoyOpen("x"), "success"))
	if !dup.Duplicate || g.revokeCount() != 1 {
		t.Fatalf("%+v revokes=%d", dup, g.revokeCount())
	}
}

func TestRevokeWithoutBoundSessionAlertsWithNoBoundSession(t *testing.T) {
	_, gw := newGateway(t)
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(gw))
	// No session sync ever happened (or the API lists none): same as before §1.
	out := r.handle(r.paymentsEvent("ev-nb", "file_open", decoyOpen("x"), "success"))
	if out.Candidate || out.Action != policy.Alert || out.Decision.RecommendedAction != policy.Revoke {
		t.Fatalf("%+v", out)
	}
	if !contains(out.Blockers, "NO_BOUND_SESSION") || contains(out.Blockers, "ADAPTER_UNAVAILABLE") {
		t.Fatalf("blockers %v", out.Blockers)
	}
	p, ok := r.api.lastPatch()
	if ok {
		t.Fatalf("nothing was done, nothing to report as a response: %+v", p)
	}
}

func TestRevokeWithoutSessionAdapterAlertsWithAdapterUnavailable(t *testing.T) {
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()))
	r.api.setSessions(activeSession("sess-x", "payments-01", "p", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)
	out := r.handle(r.paymentsEvent("ev-na", "file_open", decoyOpen("x"), "success"))
	if out.Candidate || out.Action != policy.Alert {
		t.Fatalf("%+v", out)
	}
	if !contains(out.Blockers, "ADAPTER_UNAVAILABLE") || contains(out.Blockers, "NO_BOUND_SESSION") {
		t.Fatalf("blockers %v", out.Blockers)
	}
}

func TestRevokeGatewayClaimsRevokedButSessionStillActiveIsFailed(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-liar", "active")
	g.lies = true
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(gw))
	r.api.setSessions(activeSession("sess-liar", "payments-01", "p", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)
	out := r.handle(r.paymentsEvent("ev-liar", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Failed)
	p, _ := r.api.lastPatch()
	if p.Body.Response["state"] != "failed" || p.Body.Status != "" || p.Body.Response["gateway_reply"] != "revoked" || p.Body.Response["session_state"] != "active" {
		t.Fatalf("%+v", p.Body)
	}
}

func TestRevokeInspectionUnavailableIsUnknownNotSuccess(t *testing.T) {
	ms := adapter.NewMockSessions()
	ms.Add("sess-u", "p", adapter.SessionActive)
	ms.InspectErr = errors.New("gateway timed out")
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(ms))
	r.api.setSessions(activeSession("sess-u", "payments-01", "p", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)
	out := r.handle(r.paymentsEvent("ev-unk", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Unknown)
	p, _ := r.api.lastPatch()
	if p.Body.Response["state"] != "unknown" || p.Body.Status != "" || p.Body.WorkloadState != "" {
		t.Fatalf("%+v", p.Body)
	}
	if ms.Calls()[0] != "revoke:sess-u" {
		t.Fatalf("%v", ms.Calls())
	}
}

func TestRevokeGatewayForgetsSessionAfterRevokeIsUnknown(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-gone", "active")
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(gw))
	r.api.setSessions(activeSession("sess-gone", "payments-01", "p", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)
	// The gateway revokes and immediately forgets the id (404 on the follow-up GET).
	g.mu.Lock()
	g.forget = true
	g.mu.Unlock()
	out := r.handle(r.paymentsEvent("ev-gone", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Unknown)
	p, _ := r.api.lastPatch()
	if p.Body.Response["session_state"] != "unknown" || p.Body.Status != "" {
		t.Fatalf("%+v", p.Body)
	}
}

func TestSessionChangedBetweenEvaluateAndActAborts(t *testing.T) {
	// The successor session must never be revoked for the predecessor's violation:
	// act() re-normalizes, which re-reads the session map, and Revalidate sees a
	// different candidate target.
	g, gw := newGateway(t)
	g.bind("sess-1", "active")
	g.bind("sess-2", "active")
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(gw))
	r.api.setSessions(activeSession("sess-1", "payments-01", "p", "2026-10-22T08:00:00Z"))
	syncSessions(t, r)
	// Swap the binding between the decision and act()'s refresh. Normalize reads the
	// session map before it inspects the runtime, so the swap has to land during the
	// first inspection (HandleEvent's Normalize has already bound sess-1 by then) for
	// act()'s Normalize to be the first to see sess-2.
	calls := 0
	r.mock.InspectHook = func(int) {
		calls++
		if calls == 1 {
			r.api.setSessions(activeSession("sess-2", "payments-01", "p", "2026-10-22T08:05:00Z"))
			syncSessions(t, r)
		}
	}
	out := r.handle(r.paymentsEvent("ev-swap", "file_open", decoyOpen("x"), "success"))
	mustState(t, out, journal.Aborted)
	if g.revokeCount() != 0 || g.state("sess-1") != "active" || g.state("sess-2") != "active" {
		t.Fatalf("a session was revoked: %d %s %s", g.revokeCount(), g.state("sess-1"), g.state("sess-2"))
	}
}

func TestRestartSettlesInFlightRevokeByInspectingTheGateway(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-crash", "revoked") // the revoke went out before the crash
	r := newRig(t, withRegistry(revokeRegistry(t)), withSharedProfile(activeShared()), withSessions(gw))
	j := r.c.Journal()
	key := "policy_" + repeat("d", 64)
	if _, err := j.Reserve(key, string(policy.Revoke), cidPayments, "payments-01", "ev-rcrash"); err != nil {
		t.Fatal(err)
	}
	if err := j.Transition(key, journal.Executing, map[string]any{"session_id": "sess-crash"}, 0); err != nil {
		t.Fatal(err)
	}
	r.restart()
	a, _ := r.c.Journal().Action(key)
	if a.State != journal.Verified || a.Detail["reconciled"] != true || a.Detail["session_id"] != "sess-crash" || a.Detail["adapter"] != "gateway" {
		t.Fatalf("%+v", a)
	}
	if g.revokeCount() != 0 {
		t.Fatal("reconciliation must never re-send the revoke")
	}
}

// --- §2.2 operator revoke_session -----------------------------------------------------

func revokeReq(id, session string) apiclient.OperatorAction {
	return apiclient.OperatorAction{ID: id, IncidentID: "inc_77", WorkloadID: "payments-01", Action: "revoke_session", SessionID: session,
		Operator: "rajiv", Reason: "operator confirmed the agent is compromised", Status: "requested"}
}

func TestOperatorRevokeSessionRevokesVerifiesAndReports(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-op", "active")
	r := newRig(t, withSessions(gw)) // fixture registry: payments-01 has no permitted actions; operators are not gated by that
	out := r.c.HandleOperatorAction(context.Background(), revokeReq("act_rev", "sess-op"), "poll")
	if out != OpCompleted {
		o, _ := r.c.Journal().Operator("act_rev")
		t.Fatalf("%s %+v", out, o.Detail)
	}
	if g.state("sess-op") != "revoked" {
		t.Fatal("not revoked")
	}
	res, ok := r.api.result("act_rev")
	if !ok || res.Status != "completed" || res.Detail["session_id"] != "sess-op" || res.Detail["session_state"] != "revoked" || res.Detail["adapter"] != "gateway" || res.Detail["operator"] != "rajiv" {
		t.Fatalf("%+v %v", res, ok)
	}
	if res.WorkloadState != "" {
		t.Fatalf("a revoke says nothing about the container: %q", res.WorkloadState)
	}
	g.mu.Lock()
	req := g.revokes[0]
	g.mu.Unlock()
	if req["incident_id"] != "inc_77" || req["idempotency_key"] != "operator_act_rev" || !strings.Contains(req["reason"].(string), "rajiv") {
		t.Fatalf("%v", req)
	}
	// Redelivery (the webhook and the poll both carried it) is a duplicate.
	if r.c.HandleOperatorAction(context.Background(), revokeReq("act_rev", "sess-op"), "webhook") != OpDuplicate || g.revokeCount() != 1 {
		t.Fatal("duplicate revoked again")
	}
	// Already revoked: completed without a call.
	if r.c.HandleOperatorAction(context.Background(), revokeReq("act_rev2", "sess-op"), "poll") != OpCompleted || g.revokeCount() != 1 {
		t.Fatal("already-revoked session re-revoked")
	}
	if res, _ := r.api.result("act_rev2"); res.Detail["note"] != "already revoked" {
		t.Fatalf("%+v", res)
	}
}

func TestOperatorRevokeWithoutSessionOrAdapterFails(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-x", "active")
	r := newRig(t, withSessions(gw))
	if out := r.c.HandleOperatorAction(context.Background(), revokeReq("act_nosess", ""), "poll"); out != OpFailed {
		t.Fatal(out)
	}
	res, _ := r.api.result("act_nosess")
	if res.Status != "failed" || !strings.Contains(res.Detail["reason"].(string), "no session bound") {
		t.Fatalf("%+v", res)
	}
	// Unknown to the gateway: failed, nothing revoked.
	if out := r.c.HandleOperatorAction(context.Background(), revokeReq("act_unk", "sess-nope"), "poll"); out != OpFailed {
		t.Fatal(out)
	}
	if res, _ := r.api.result("act_unk"); !strings.Contains(res.Detail["reason"].(string), "does not know") {
		t.Fatalf("%+v", res)
	}
	if g.revokeCount() != 0 {
		t.Fatal("revoke sent for a session that cannot be revoked")
	}

	// No adapter at all: failed with ADAPTER_UNAVAILABLE, not ignored (the operator
	// must learn this node cannot do it).
	r2 := newRig(t)
	if out := r2.c.HandleOperatorAction(context.Background(), revokeReq("act_noad", "sess-x"), "poll"); out != OpFailed {
		t.Fatal(out)
	}
	if res, _ := r2.api.result("act_noad"); !strings.Contains(res.Detail["reason"].(string), "ADAPTER_UNAVAILABLE") {
		t.Fatalf("%+v", res)
	}
	// Another node's workload is still ignored.
	other := revokeReq("act_other", "sess-x")
	other.WorkloadID = "not-ours"
	if out := r.c.HandleOperatorAction(context.Background(), other, "poll"); out != OpIgnored {
		t.Fatal(out)
	}
}

func TestOperatorRevokeArrivesByPollAndWebhook(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-poll", "active")
	g.bind("sess-hook", "active")
	r := newRig(t, withSessions(gw))
	// Poll: the API's queue carries session_id (main.ser_action).
	r.api.enqueue(revokeReq("act_poll", "sess-poll"))
	r.c.PollOnce(context.Background())
	if g.state("sess-poll") != "revoked" {
		t.Fatal("poll delivery not executed")
	}
	if res, ok := r.api.result("act_poll"); !ok || res.Status != "completed" {
		t.Fatalf("%+v %v", res, ok)
	}
	// Webhook: signed payload with session_id.
	secret := []byte("0123456789abcdef0123456789abcdef")
	srv := &Server{C: r.c, WebhookSecret: secret}
	body, _ := json.Marshal(revokeReq("act_hook", "sess-hook"))
	req := httptest.NewRequest(http.MethodPost, "/river3/actions", strings.NewReader(string(body)))
	req.Header = Sign(secret, body, r.now.Unix(), "d-hook-1")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || g.state("sess-hook") != "revoked" {
		t.Fatalf("%d %s %s", rec.Code, rec.Body.String(), g.state("sess-hook"))
	}
	if res, ok := r.api.result("act_hook"); !ok || res.Status != "completed" || res.Detail["session_id"] != "sess-hook" {
		t.Fatalf("%+v %v", res, ok)
	}
}

func TestOperatorRevokeClaimStuckAfterCrashIsSettledByInspection(t *testing.T) {
	g, gw := newGateway(t)
	g.bind("sess-rc", "revoked") // the call went out before the crash
	g.bind("sess-rf", "active")  // it did not
	jpath := claimedJournalRevoke(t, "act_rc", "sess-rc")
	r := newRig(t, withJournal(jpath), withSessions(gw))
	o, _ := r.c.Journal().Operator("act_rc")
	if o.Result != "completed" || o.Detail["session_state"] != "revoked" || o.Detail["reconciled"] != true {
		t.Fatalf("%+v", o)
	}
	jpath2 := claimedJournalRevoke(t, "act_rf", "sess-rf")
	r2 := newRig(t, withJournal(jpath2), withSessions(gw))
	o2, _ := r2.c.Journal().Operator("act_rf")
	if o2.Result != "failed" || o2.Detail["reason"] != "controller restarted mid-action" || o2.Detail["session_state"] != "active" {
		t.Fatalf("%+v", o2)
	}
	if g.revokeCount() != 0 {
		t.Fatal("reconciliation re-sent a revoke")
	}
}

func claimedJournalRevoke(t *testing.T, actionID, session string) string {
	t.Helper()
	p := t.TempDir() + "/crashed.jsonl"
	j, err := journal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimOperator(actionID, map[string]any{"action": "revoke_session", "workload_id": "payments-01", "operator": "rajiv", "source": "poll", "session_id": session, "incident_id": "inc_77"}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	return p
}

// --- §5 domain egress ------------------------------------------------------------------

// fakeResolver is the injected DNS. Answers are per name; a missing name is an error.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	errs    map[string]error
	calls   map[string]int
}

func newResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][]netip.Addr{}, errs: map[string]error{}, calls: map[string]int{}}
}

func (f *fakeResolver) set(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	f.answers[name] = out
	delete(f.errs, name)
}

func (f *fakeResolver) fail(name string, err error) {
	f.mu.Lock()
	f.errs[name] = err
	f.mu.Unlock()
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[host]++
	if network != "ip" {
		return nil, errors.New("fake resolver: network must be ip (A and AAAA)")
	}
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	a, ok := f.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return append([]netip.Addr(nil), a...), nil
}

func domainShared() policy.Profile {
	p := sharedProfile() // shadow: a connect out of scope alerts, which is all we need to see
	p.EgressAllowDomains = []string{"api.example.com", "*.cdn.example.net"}
	return p
}

func (r *rig) connect(id, ip string) Outcome {
	return r.handle(r.paymentsEvent(id, "net_connect", normalize.RawTarget{IP: ip, Port: 443}, "success"))
}

func TestEgressDomainResolvesToInScopeAndRefreshFollowsChanges(t *testing.T) {
	res := newResolver()
	res.set("api.example.com", "203.0.113.10", "2001:db8::10")
	res.set("cdn.example.net", "203.0.113.20")
	eg := &Egress{Resolver: res, Timeout: time.Second}
	r := newRig(t, withSharedProfile(domainShared()), withEgress(eg))
	// New sets go through ApplyPolicy (resolve, then derive); the rig's New stored the
	// base through SetPolicy, so resolve here exactly as the daemon does at startup.
	r.c.ApplyPolicy(context.Background(), r.c.Policy())

	if out := r.connect("ev-e1", "203.0.113.10"); out.Status != policy.InScope {
		t.Fatalf("resolved A record out of scope: %+v", out)
	}
	if out := r.connect("ev-e2", "2001:db8::10"); out.Status != policy.InScope {
		t.Fatalf("resolved AAAA record out of scope: %+v", out)
	}
	if out := r.connect("ev-e3", "203.0.113.20"); out.Status != policy.InScope {
		t.Fatalf("wildcard apex out of scope: %+v", out)
	}
	if out := r.connect("ev-e4", "10.20.1.1"); out.Status != policy.InScope {
		t.Fatalf("the profile's own CIDR must still be in scope: %+v", out)
	}
	if out := r.connect("ev-e5", "203.0.113.99"); out.Status != policy.Violation || out.Decision.Findings[0].Code != "EGRESS_OUTSIDE_SCOPE" {
		t.Fatalf("unresolved address let in: %+v", out)
	}
	// The original profile body is untouched; the derived table is visible.
	pol := r.c.Policy()
	if len(pol.Profiles["payment-service"].EgressAllow) != 1 || pol.Profiles["payment-service"].EgressAllow[0] != "10.20.0.0/16" {
		t.Fatalf("original profile mutated: %v", pol.Profiles["payment-service"].EgressAllow)
	}
	got := pol.Egress["payment-service"]
	if len(got) != 3 || !contains(got, "203.0.113.10/32") || !contains(got, "203.0.113.20/32") || !contains(got, "2001:db8::10/128") {
		t.Fatalf("derived prefixes %v", got)
	}
	if _, ok := pol.Egress["diagnostic-worker"]; ok {
		t.Fatal("a profile without domains must not appear in the table")
	}

	// The name moves: after the refresh the new address is in scope and the old one out.
	res.set("api.example.com", "203.0.113.11")
	r.c.RefreshEgress(context.Background())
	if out := r.connect("ev-e6", "203.0.113.11"); out.Status != policy.InScope {
		t.Fatalf("new address out of scope after refresh: %+v", out)
	}
	if out := r.connect("ev-e7", "203.0.113.10"); out.Status != policy.Violation {
		t.Fatalf("old address still in scope after refresh: %+v", out)
	}
	// A refresh that changes nothing swaps nothing.
	before := r.c.Policy()
	r.c.RefreshEgress(context.Background())
	if r.c.Policy() != before {
		t.Fatal("unchanged answers must not swap the policy")
	}
	st := r.c.EgressStatus()
	if st["addresses"] != 2 || len(st["names"].([]string)) != 2 || len(st["failing"].([]string)) != 0 {
		t.Fatalf("status %v", st)
	}
}

func TestEgressResolverErrorKeepsPreviousAddresses(t *testing.T) {
	res := newResolver()
	res.set("api.example.com", "203.0.113.10")
	res.set("cdn.example.net", "203.0.113.20")
	eg := &Egress{Resolver: res, Timeout: time.Second}
	r := newRig(t, withSharedProfile(domainShared()), withEgress(eg))
	r.c.ApplyPolicy(context.Background(), r.c.Policy())
	if out := r.connect("ev-k1", "203.0.113.10"); out.Status != policy.InScope {
		t.Fatalf("%+v", out)
	}
	res.fail("api.example.com", errors.New("SERVFAIL"))
	before := r.c.Policy()
	r.c.RefreshEgress(context.Background())
	r.c.RefreshEgress(context.Background()) // second failure: logged once, still kept
	if r.c.Policy() != before {
		t.Fatal("a resolver failure must not change the enforced set")
	}
	if out := r.connect("ev-k2", "203.0.113.10"); out.Status != policy.InScope {
		t.Fatalf("previous address dropped on resolver error: %+v", out)
	}
	st := r.c.EgressStatus()
	if f := st["failing"].([]string); len(f) != 1 || f[0] != "api.example.com" {
		t.Fatalf("status %v", st)
	}
	// Recovery with a new answer is applied.
	res.set("api.example.com", "203.0.113.12")
	r.c.RefreshEgress(context.Background())
	if out := r.connect("ev-k3", "203.0.113.12"); out.Status != policy.InScope {
		t.Fatalf("%+v", out)
	}
	if out := r.connect("ev-k4", "203.0.113.10"); out.Status != policy.Violation {
		t.Fatalf("%+v", out)
	}
	if len(r.c.EgressStatus()["failing"].([]string)) != 0 {
		t.Fatal("recovered name still failing")
	}
	// Per-name timeout: a resolver that hangs is cut off at Egress.Timeout.
	slow := &slowResolver{}
	eg2 := &Egress{Resolver: slow, Timeout: 20 * time.Millisecond}
	start := time.Now()
	eg2.Resolve(context.Background(), []string{"a.example", "b.example"})
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("resolution not bounded: %s", d)
	}
	if len(eg2.Status()["failing"].([]string)) != 2 {
		t.Fatalf("%v", eg2.Status())
	}
}

type slowResolver struct{}

func (slowResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestEgressSurvivesPolicySyncAndKeepsTheAPIRevision(t *testing.T) {
	res := newResolver()
	res.set("api.example.com", "203.0.113.10")
	res.set("cdn.example.net", "203.0.113.20")
	eg := &Egress{Resolver: res, Timeout: time.Second}
	r := newRig(t, withSharedProfile(domainShared()), withEgress(eg))
	// The API publishes a bundle with the domain profile.
	docs := []json.RawMessage{}
	for _, p := range []policy.Profile{activeProfile(), domainShared()} {
		b, _ := json.Marshal(p)
		docs = append(docs, b)
	}
	r.api.mu.Lock()
	r.api.bundle = apiclient.PolicyBundle{Revision: "rev-domains-1", Profiles: docs}
	r.api.mu.Unlock()
	if err := r.c.SyncPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	pol := r.c.Policy()
	if pol.Revision != "rev-domains-1" || len(pol.Egress["payment-service"]) != 2 {
		t.Fatalf("revision %q egress %v", pol.Revision, pol.Egress)
	}
	if out := r.connect("ev-p1", "203.0.113.10"); out.Status != policy.InScope {
		t.Fatalf("%+v", out)
	}
	// The status reported to the API is the bundle's revision, not something derived.
	r.api.mu.Lock()
	rep := r.api.reports[len(r.api.reports)-1]
	r.api.mu.Unlock()
	if rep.ActiveRevision != "rev-domains-1" || rep.SeenRevision != "rev-domains-1" || rep.Error != "" {
		t.Fatalf("%+v", rep)
	}
	// An egress refresh keeps the revision; a policy sync afterwards sees no change.
	res.set("api.example.com", "203.0.113.11")
	r.c.RefreshEgress(context.Background())
	if r.c.Policy().Revision != "rev-domains-1" {
		t.Fatal("refresh changed the revision")
	}
	if err := r.c.SyncPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out := r.connect("ev-p2", "203.0.113.11"); out.Status != policy.InScope {
		t.Fatalf("sync after refresh lost the resolved address: %+v", out)
	}
}

// --- normalizer: team + inline ---------------------------------------------------------

func TestSensorTeamAndInlineReachTheIncidentAndTheRegistration(t *testing.T) {
	r := newRig(t)
	env := r.event("ev-team", "file_open", decoyOpen("x"), "blocked")
	env.Raw.Facts.Workload.Team = "payments"
	env.Raw.Facts.Inline = true
	out := r.handle(env)
	if out.Status != policy.Violation || out.Candidate {
		t.Fatalf("%+v", out)
	}
	inc, ok := r.api.incident(out.IncidentID)
	if !ok {
		t.Fatal("incident not posted")
	}
	reason := inc["reason"].(string)
	if !strings.Contains(reason, normalize.InlineNote) || !strings.Contains(reason, normalize.BlockedNote) {
		t.Fatalf("reason %q", reason)
	}
	facts := inc["events"].([]any)[0].(map[string]any)["facts"].(map[string]any)
	if facts["inline"] != true || facts["blocked_inline"] != true || facts["workload"].(map[string]any)["team"] != "payments" {
		t.Fatalf("facts %v", facts)
	}
	// The registration carried the team (the fixture registry has none for worker-01).
	r.api.mu.Lock()
	defer r.api.mu.Unlock()
	if !r.api.workloads["worker-01"] {
		t.Fatal("workload not registered")
	}
}
