package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLRules(t *testing.T) {
	for _, bad := range []string{"http://river3.internal", "https://user:pw@host", "https://host/?x=1", "ftp://host", ""} {
		if _, err := New(Config{BaseURL: bad, ContainmentToken: "t"}); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := New(Config{BaseURL: "https://host", ContainmentToken: ""}); err == nil {
		t.Fatal("empty token accepted")
	}
	for _, ok := range []string{"http://127.0.0.1:8000", "http://localhost:8000/", "https://river3.internal"} {
		if _, err := New(Config{BaseURL: ok, ContainmentToken: "t"}); err != nil {
			t.Fatalf("rejected %q: %v", ok, err)
		}
	}
}

func TestRetriesAndTokens(t *testing.T) {
	var hits atomic.Int32
	var seenAuth, seenPath, seenQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		seenAuth, seenPath, seenQuery = r.Header.Get("Authorization"), r.URL.Path, r.URL.RawQuery
		switch {
		case r.URL.Path == "/api/v1/incidents" && n == 1:
			w.WriteHeader(503) // retried
		case r.URL.Path == "/api/v1/incidents":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"inc_1"}`))
		case r.URL.Path == "/api/v1/actions/a1/result":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"detail":"action already completed"}`))
		case r.URL.Path == "/api/v1/actions":
			_, _ = w.Write([]byte(`[{"id":"a1","workload_id":"w","action":"resume"}]`))
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "http://evil.example/", 302)
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, ContainmentToken: "contain", PolicyToken: "policy", Backoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	id, err := c.CreateIncident(ctx, map[string]any{})
	if err != nil || id != "inc_1" || hits.Load() != 2 || seenAuth != "Bearer policy" {
		t.Fatalf("id=%s err=%v hits=%d auth=%s", id, err, hits.Load(), seenAuth)
	}
	if err := c.PatchResponse(ctx, "inc_1", ResponseUpdate{Response: map[string]any{}}); err != nil || seenAuth != "Bearer contain" {
		t.Fatal(err, seenAuth)
	}
	acts, err := c.QueuedActions(ctx, "requested")
	if err != nil || len(acts) != 1 || seenPath != "/api/v1/actions" || seenQuery != "limit=200&status=requested" {
		t.Fatalf("%v %v %s %s", acts, err, seenPath, seenQuery)
	}
	err = c.PostResult(ctx, "a1", ActionResult{Status: "completed"})
	if !IsStatus(err, http.StatusConflict) {
		t.Fatalf("409 not surfaced: %v", err)
	}
	// 4xx is not retried
	before := hits.Load()
	_ = c.PostResult(ctx, "a1", ActionResult{Status: "completed"})
	if hits.Load() != before+1 {
		t.Fatal("4xx was retried")
	}
	// redirects are not followed (token must not leak)
	if _, err := c.do(ctx, "contain", http.MethodGet, "/redirect", nil, nil, nil); !IsStatus(err, 302) {
		t.Fatalf("redirect followed or mis-handled: %v", err)
	}
}
