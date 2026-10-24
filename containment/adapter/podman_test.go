package adapter

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fakeLibpod serves the handful of libpod routes the adapter uses over a unix socket.
func fakeLibpod(t *testing.T, state *string) string {
	t.Helper()
	cid := strings.Repeat("a", 64)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v4.0.0/libpod/containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != cid {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"Id":"` + cid + `","State":{"Status":"` + *state + `","StartedAt":"2026-10-19T09:00:00Z"}}`))
	})
	mux.HandleFunc("POST /v4.0.0/libpod/containers/{id}/pause", func(w http.ResponseWriter, r *http.Request) {
		*state = "paused"
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v4.0.0/libpod/containers/{id}/unpause", func(w http.ResponseWriter, r *http.Request) {
		*state = "running"
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v4.0.0/libpod/containers/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("timeout") != "10" {
			w.WriteHeader(400)
			return
		}
		*state = "exited"
		w.WriteHeader(204)
	})
	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func TestPodmanAgainstFakeSocket(t *testing.T) {
	state := "running"
	p, err := NewPodman(fakeLibpod(t, &state))
	if err != nil {
		t.Fatal(err)
	}
	cid := strings.Repeat("a", 64)
	ctx := context.Background()

	info, err := p.Inspect(ctx, cid)
	if err != nil || info.Status != Running || info.ContainerID != cid || info.Generation != "2026-10-19T09:00:00Z" {
		t.Fatalf("%+v %v", info, err)
	}
	if err := p.Pause(ctx, cid); err != nil {
		t.Fatal(err)
	}
	if info, _ = p.Inspect(ctx, cid); info.Status != Paused {
		t.Fatal(info)
	}
	if err := p.Resume(ctx, cid); err != nil {
		t.Fatal(err)
	}
	if err := p.Terminate(ctx, cid); err != nil {
		t.Fatal(err)
	}
	if info, _ = p.Inspect(ctx, cid); info.Status != Exited {
		t.Fatal(info)
	}
	if info, err = p.Inspect(ctx, strings.Repeat("b", 64)); err != nil || info.Status != Missing {
		t.Fatalf("%+v %v", info, err)
	}
	// names and short ids are refused before any request is made
	for _, bad := range []string{"worker", "aaaaaaaaaaaa", strings.Repeat("A", 64)} {
		if err := p.Pause(ctx, bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := NewPodman("relative/path.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
}

func TestMockFailureSwitches(t *testing.T) {
	m := NewMock()
	cid := strings.Repeat("a", 64)
	m.Add(cid, "g1", Running)
	m.PauseNoEffect = true
	if err := m.Pause(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	if info, _ := m.Inspect(context.Background(), cid); info.Status != Running {
		t.Fatal("PauseNoEffect changed state")
	}
	m.Unsupported = true
	if len(m.Actions()) != 0 {
		t.Fatal("unsupported mock still advertises actions")
	}
}
