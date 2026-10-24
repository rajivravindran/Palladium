package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeEnroll(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "enroll.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnrollmentValidation(t *testing.T) {
	good := `[{"asset_id":"worker-01","name":"W","profile":"p","kind":"ai_worker","container_id":"` + cidA + `"}]`
	if _, err := loadEnrollments(writeEnroll(t, good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"short id":      strings.Replace(good, cidA, "aaaaaaaaaaaa", 1),
		"unknown field": strings.Replace(good, `"kind"`, `"trusted":true,"kind"`, 1),
		"bad kind":      strings.Replace(good, "ai_worker", "robot", 1),
		"no identity":   `[{"asset_id":"w","name":"W","profile":"p","kind":"ai_worker"}]`,
		"duplicate":     strings.TrimSuffix(good, "]") + "," + strings.TrimPrefix(good, "["),
		"empty":         `[]`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := loadEnrollments(writeEnroll(t, body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

type fakeRuntime struct {
	pids map[string]uint32
	err  error
}

func (f fakeRuntime) PID(_ context.Context, id string) (uint32, error) {
	if f.err != nil {
		return 0, f.err
	}
	p, ok := f.pids[id]
	if !ok {
		return 0, errNotRunning
	}
	return p, nil
}

func TestEnrollerUsesShortcutsAndRuntime(t *testing.T) {
	var applied map[uint32]bool
	var logs []string
	e := &Enroller{
		Enrollments: []Enrollment{
			{AssetID: "direct", Name: "D", Profile: "p", Kind: "ai_worker", Mntns: 4026532100},
			{AssetID: "gone", Name: "G", Profile: "p", Kind: "ai_worker", ContainerID: strings.Repeat("c", 64)},
			{AssetID: "dup1", Name: "x", Profile: "p", Kind: "ai_worker", Mntns: 77},
			{AssetID: "dup2", Name: "y", Profile: "p", Kind: "shared_service", Mntns: 77},
		},
		Runtime:    fakeRuntime{pids: map[string]uint32{}},
		Watch:      newWatchlist(),
		SetWatched: func(d map[uint32]bool) error { applied = d; return nil },
		Log:        func(f string, a ...any) { logs = append(logs, f) },
	}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !applied[4026532100] || applied[77] || len(applied) != 1 {
		t.Fatalf("applied %v", applied)
	}
	if ref, ok := e.Watch.Lookup(4026532100); !ok || ref.ID != "direct" {
		t.Fatal(ref)
	}
	if _, ok := e.Watch.LookupContainer(strings.Repeat("c", 12)); !ok {
		t.Fatal("container id must be resolvable even while the container is down (Falco path)")
	}
	if len(logs) != 2 { // "gone" not running + the shared namespace
		t.Fatalf("logs %v", logs)
	}
}

func TestMntnsOfParsesProcLink(t *testing.T) {
	if _, err := mntnsOf(uint32(os.Getpid())); err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			t.Skip("no /proc here")
		}
		t.Fatal(err)
	}
}

func TestWatchlistPrefixAmbiguity(t *testing.T) {
	w := newWatchlist()
	w.replace(nil, map[string]WorkloadRef{strings.Repeat("a", 64): {ID: "x"}, "a" + strings.Repeat("b", 63): {ID: "y"}})
	if _, ok := w.LookupContainer("aaaaaaaaaaaa"); !ok {
		t.Fatal("unique 12-char prefix should resolve")
	}
	if _, ok := w.LookupContainer("a"); ok {
		t.Fatal("ambiguous/short prefix resolved")
	}
}

// --- sinks ---------------------------------------------------------------------------

func TestControllerSinkDeliversAndGivesUpOn4xx(t *testing.T) {
	var hits atomic.Int32
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth = r.Header.Get("Authorization")
		var ev Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil || r.URL.Path != "/v1/events" {
			w.WriteHeader(400)
			return
		}
		if ev.Facts.ID == "reject-me" {
			w.WriteHeader(422)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	s, err := newControllerSink(srv.URL, "dev-sensor-token", 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Emit(Event{Facts: Facts{ID: "ok-1", Kind: KindFileOpen}})
	s.Emit(Event{Facts: Facts{ID: "reject-me", Kind: KindFileOpen}})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (s.sent.Load() < 1 || s.failed.Load() < 1) {
		time.Sleep(10 * time.Millisecond)
	}
	st := s.Stats()
	if st.Sent != 1 || st.Failed != 1 || hits.Load() != 2 || auth != "Bearer dev-sensor-token" {
		t.Fatalf("%+v hits=%d auth=%s", st, hits.Load(), auth)
	}
}

func TestAPISinkBatchesAndSplitsOnConflict(t *testing.T) {
	var posts atomic.Int32
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		var batch []apiEvent
		_ = json.NewDecoder(r.Body).Decode(&batch)
		for _, e := range batch {
			if seen[e.ID] {
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"detail":"duplicate event id"}`))
				return
			}
		}
		for _, e := range batch {
			seen[e.ID] = true
			if e.WorkloadID == "" || e.Facts["id"] != e.ID {
				w.WriteHeader(422)
				return
			}
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	s, err := newAPISink(srv.URL, "dev-ingest-token", 100, 10, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	ev := func(id string) Event {
		return Event{Facts: Facts{ID: id, Kind: KindFileOpen, Outcome: OutcomeSuccess, Workload: WorkloadRef{ID: "worker-01"}, Received: uint64(time.Now().UnixNano())}}
	}
	s.Emit(ev("a"))
	s.Emit(ev("b"))
	time.Sleep(150 * time.Millisecond)
	s.Emit(ev("a")) // duplicate inside a batch with a fresh one
	s.Emit(ev("c"))
	time.Sleep(300 * time.Millisecond)
	st := s.Stats()
	if st.Sent != 3 || st.Duplicates != 1 || st.Failed != 0 {
		t.Fatalf("%+v posts=%d", st, posts.Load())
	}
}

func TestAPIClientURLRules(t *testing.T) {
	for _, bad := range []string{"http://river3.internal:8000", "https://u:p@host", "https://host/?q=1", ""} {
		if _, err := newAPIClient(bad, "t"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := newAPIClient("https://host", ""); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := newAPIClient("http://127.0.0.1:8787", "t"); err != nil {
		t.Fatal(err)
	}
}

func TestShadowEvalUsesPolicyEngine(t *testing.T) {
	if _, err := os.Stat("../policy/examples/profiles"); errors.Is(err, os.ErrNotExist) {
		t.Skip("policy examples not alongside")
	}
	var out strings.Builder
	sh, err := newShadowEval("../policy/examples/profiles", &out)
	if err != nil {
		t.Fatal(err)
	}
	sh.Emit(Event{Facts: Facts{ID: "s1", Kind: KindFileOpen, Outcome: OutcomeSuccess, Received: uint64(time.Now().UnixNano()),
		Workload: WorkloadRef{ID: "worker-01", Profile: "diagnostic-worker", ContainerID: cidA},
		Target:   Target{Path: "/opt/config/.db_recovery_creds", Access: "read"}}})
	if !strings.Contains(out.String(), `"DECOY_OPEN"`) || !strings.Contains(out.String(), `"shadow":"VIOLATION"`) {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), `"candidate"`) {
		t.Fatal("shadow evaluation must never produce a candidate")
	}
}
