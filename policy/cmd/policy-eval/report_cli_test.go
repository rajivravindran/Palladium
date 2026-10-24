package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"river3.local/policy/report"
)

func TestReplayReportsOnlyViolations(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer s.Close()
	rep, err := report.New(report.Config{BaseURL: s.URL, Token: "m-policy"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runWith(context.Background(), "../../examples/profiles", bytes.NewReader(data), &out, rep); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(paths, ",")
	if got != "/api/v1/workloads,/api/v1/incidents" {
		t.Fatalf("expected one enrollment and one incident (the decoy), got %s", got)
	}
	st := rep.Stats()
	if st.Posted != 1 || st.SkippedUnknown != 1 {
		t.Fatalf("%+v", st)
	}
}
