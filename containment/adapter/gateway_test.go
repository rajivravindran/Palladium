package adapter

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
	"strings"
	"sync"
	"testing"
	"time"

	"river3.local/containment/sign"
	policy "river3.local/policy"
)

const gwSecret = "0123456789abcdef0123456789abcdef-gateway-secret"

// fakeGateway is a reference-shaped customer gateway (CONTRACTS.md §2.1): it verifies
// the controller's signature exactly as the controller verifies the API's webhook,
// and answers the two session endpoints.
type fakeGateway struct {
	mu        sync.Mutex
	srv       *httptest.Server
	sessions  map[string]string // id -> state
	principal map[string]string
	revokes   []map[string]any
	seen      map[string]bool // delivery ids
	badSig    int
	// behaviour switches
	revokeLies    bool          // answer "revoked" but keep the session active
	revokeAnswers string        // override the state the revoke reply claims
	inspectStatus int           // non-zero: GET answers this status with an error body
	delay         time.Duration // sleep before answering
	extraField    bool          // add an unknown field to the inspect reply
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{sessions: map[string]string{}, principal: map[string]string{}, seen: map[string]bool{}}
	mux := http.NewServeMux()
	verify := func(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
		body, _ := io.ReadAll(r.Body)
		ts, delivery, sig := r.Header.Get("X-River3-Timestamp"), r.Header.Get("X-River3-Delivery"), r.Header.Get("X-River3-Signature")
		mac := hmac.New(sha256.New, []byte(gwSecret))
		mac.Write(sign.Base(ts, delivery, body))
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		g.mu.Lock()
		defer g.mu.Unlock()
		if ts == "" || delivery == "" || sig != want || g.seen[delivery] {
			g.badSig++
			http.Error(w, `{"detail":"bad signature"}`, 401)
			return nil, false
		}
		g.seen[delivery] = true
		return body, true
	}
	mux.HandleFunc("POST /v1/sessions/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		body, ok := verify(w, r)
		if !ok {
			return
		}
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.delay > 0 {
			time.Sleep(g.delay)
		}
		id := r.PathValue("id")
		st, known := g.sessions[id]
		if !known {
			http.Error(w, `{"detail":"no such session"}`, 404)
			return
		}
		req["_id"] = id
		g.revokes = append(g.revokes, req)
		if !g.revokeLies && st == "active" {
			g.sessions[id] = "revoked"
		}
		answer := g.sessions[id]
		if g.revokeLies {
			answer = "revoked"
		}
		if g.revokeAnswers != "" {
			answer = g.revokeAnswers
		}
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(map[string]any{"state": answer})
	})
	mux.HandleFunc("GET /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := verify(w, r); !ok {
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.delay > 0 {
			time.Sleep(g.delay)
		}
		if g.inspectStatus != 0 {
			http.Error(w, `{"detail":"gateway unhappy"}`, g.inspectStatus)
			return
		}
		id := r.PathValue("id")
		st, known := g.sessions[id]
		if !known {
			http.Error(w, `{"detail":"no such session"}`, 404)
			return
		}
		reply := map[string]any{"state": st, "principal": g.principal[id], "started_at": "2026-10-22T08:00:00Z"}
		if g.extraField {
			reply["surprise"] = true
		}
		_ = json.NewEncoder(w).Encode(reply)
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) add(id, principal, state string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sessions[id] = state
	g.principal[id] = principal
}

func newTestGateway(t *testing.T, url string) *Gateway {
	t.Helper()
	gw, err := NewGateway(url, []byte(gwSecret))
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

func TestGatewayURLAndSecretRules(t *testing.T) {
	for _, bad := range []string{"http://gateway.internal", "https://u:p@gw", "https://gw/?x=1", "ftp://gw", ""} {
		if _, err := NewGateway(bad, []byte(gwSecret)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := NewGateway("https://gw.example", []byte("short")); err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("short secret accepted: %v", err)
	}
	for _, ok := range []string{"http://127.0.0.1:9000", "http://localhost:9000/", "https://gw.example/base"} {
		if _, err := NewGateway(ok, []byte(gwSecret)); err != nil {
			t.Fatalf("rejected %q: %v", ok, err)
		}
	}
	gw := newTestGateway(t, "https://gw.example")
	if gw.Name() != "gateway" || len(gw.Actions()) != 1 || gw.Actions()[0] != policy.Revoke {
		t.Fatalf("%s %v", gw.Name(), gw.Actions())
	}
}

func TestGatewayRevokeSignsLikeTheWebhookAndVerifiesAfterwards(t *testing.T) {
	g := newFakeGateway(t)
	g.add("sess-1", "svc-deployer@prod", "active")
	gw := newTestGateway(t, g.srv.URL)
	ctx := context.Background()

	before, err := gw.InspectSession(ctx, "sess-1")
	if err != nil || before.State != SessionActive || before.Principal != "svc-deployer@prod" || before.ID != "sess-1" {
		t.Fatalf("%+v %v", before, err)
	}
	st, err := gw.Revoke(ctx, "sess-1", "river3 payment-service: DECOY_READ", "ev-1", "policy_"+strings.Repeat("a", 64))
	if err != nil || st != SessionRevoked {
		t.Fatalf("%s %v", st, err)
	}
	after, err := gw.InspectSession(ctx, "sess-1")
	if err != nil || after.State != SessionRevoked {
		t.Fatalf("%+v %v", after, err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.badSig != 0 {
		t.Fatalf("%d requests failed the gateway's signature check", g.badSig)
	}
	if len(g.revokes) != 1 {
		t.Fatalf("revokes %v", g.revokes)
	}
	req := g.revokes[0]
	if req["_id"] != "sess-1" || req["reason"] != "river3 payment-service: DECOY_READ" || req["incident_id"] != "ev-1" || req["idempotency_key"] != "policy_"+strings.Repeat("a", 64) {
		t.Fatalf("request body %v", req)
	}
	if len(req) != 4 { // reason, incident_id, idempotency_key + our _id marker: nothing else goes on the wire
		t.Fatalf("unexpected fields in revoke body: %v", req)
	}
	if len(g.seen) != 3 {
		t.Fatalf("every request must carry a fresh delivery id; saw %d", len(g.seen))
	}
}

func TestGatewayRevokeReplyIsAClaimInspectDecides(t *testing.T) {
	g := newFakeGateway(t)
	g.add("sess-2", "p", "active")
	g.revokeLies = true // says revoked, does nothing
	gw := newTestGateway(t, g.srv.URL)
	st, err := gw.Revoke(context.Background(), "sess-2", "r", "i", "k")
	if err != nil || st != SessionRevoked {
		t.Fatalf("%s %v", st, err)
	}
	info, err := gw.InspectSession(context.Background(), "sess-2")
	if err != nil || info.State != SessionActive {
		t.Fatalf("inspect must show the truth: %+v %v", info, err)
	}
}

func TestGatewayStateMapping(t *testing.T) {
	g := newFakeGateway(t)
	g.add("ended-1", "p", "ended")
	g.add("rev-1", "p", "revoked")
	g.add("unk-1", "p", "unknown")
	gw := newTestGateway(t, g.srv.URL)
	ctx := context.Background()
	for id, want := range map[string]SessionState{"ended-1": SessionEnded, "rev-1": SessionRevoked, "unk-1": SessionUnknown} {
		info, err := gw.InspectSession(ctx, id)
		if err != nil || info.State != want {
			t.Fatalf("%s: %+v %v", id, info, err)
		}
	}
	// 404 on inspect is the inspected state "unknown", not an error.
	info, err := gw.InspectSession(ctx, "never-bound")
	if err != nil || info.State != SessionUnknown {
		t.Fatalf("%+v %v", info, err)
	}
	// 404 on revoke is ErrSessionUnknown.
	if st, err := gw.Revoke(ctx, "never-bound", "r", "i", "k"); !errors.Is(err, ErrSessionUnknown) || st != SessionUnknown {
		t.Fatalf("%s %v", st, err)
	}
	// A revoke reply outside the contract vocabulary is an error, not a state.
	g.revokeAnswers = "maybe"
	g.add("sess-3", "p", "active")
	if _, err := gw.Revoke(ctx, "sess-3", "r", "i", "k"); err == nil || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("%v", err)
	}
	g.revokeAnswers = ""
	// A 5xx on inspect is an error (the controller journals UNKNOWN).
	g.inspectStatus = 503
	if _, err := gw.InspectSession(ctx, "rev-1"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
	g.inspectStatus = 0
	// Strict JSON: an unknown field in the gateway's reply is a mis-versioned gateway.
	g.extraField = true
	if _, err := gw.InspectSession(ctx, "rev-1"); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("%v", err)
	}
}

func TestGatewayTimeoutAndMalformedIDs(t *testing.T) {
	g := newFakeGateway(t)
	g.add("slow", "p", "active")
	g.delay = 300 * time.Millisecond
	gw := newTestGateway(t, g.srv.URL)
	gw.timeout = 50 * time.Millisecond
	if _, err := gw.Revoke(context.Background(), "slow", "r", "i", "k"); err == nil {
		t.Fatal("timeout not reported")
	}
	if _, err := gw.InspectSession(context.Background(), "slow"); err == nil {
		t.Fatal("timeout not reported")
	}
	gw.timeout = GatewayTimeout
	for _, bad := range []string{"", "../x", "a b", strings.Repeat("x", 129)} {
		if _, err := gw.Revoke(context.Background(), bad, "r", "i", "k"); err == nil {
			t.Fatalf("malformed id %q sent", bad)
		}
		if _, err := gw.InspectSession(context.Background(), bad); err == nil {
			t.Fatalf("malformed id %q sent", bad)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.revokes {
		if r["_id"] != "slow" {
			t.Fatalf("a malformed id reached the gateway: %v", r)
		}
	}
}

func TestGatewayNeverFollowsRedirects(t *testing.T) {
	var leaked int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked++; w.WriteHeader(200) }))
	defer evil.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	gw := newTestGateway(t, redir.URL)
	if _, err := gw.Revoke(context.Background(), "s", "r", "i", "k"); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("%v", err)
	}
	if leaked != 0 {
		t.Fatal("signed request followed a redirect")
	}
}
