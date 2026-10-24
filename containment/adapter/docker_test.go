package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeEngine serves the Docker Engine API routes the adapter uses, under /v1.43,
// with the status codes the real daemon returns (verified against Docker 29, API
// 1.56: 204 on a state change, 304 on stop of a stopped container, 409 on pause of
// a paused one, 404 for an unknown id).
type fakeEngine struct {
	mu         sync.Mutex
	containers map[string]*fakeContainer
	lastList   string // raw query of the last GET /containers/json
}

type fakeContainer struct {
	status, startedAt, name string
	labels                  map[string]string
}

func newFakeEngine(t *testing.T) (*fakeEngine, string) {
	t.Helper()
	e := &fakeEngine{containers: map[string]*fakeContainer{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1.43/containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		c, ok := e.containers[r.PathValue("id")]
		if !ok {
			http.Error(w, `{"message":"No such container"}`, 404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": r.PathValue("id"), "Name": "/" + c.name,
			"State": map[string]any{"Status": c.status, "StartedAt": c.startedAt}, "Config": map[string]any{"Labels": c.labels}})
	})
	mux.HandleFunc("GET /v1.43/containers/json", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.lastList = r.URL.RawQuery
		rows := []map[string]any{}
		for id, c := range e.containers {
			if c.status != "running" && c.status != "paused" && c.status != "restarting" {
				continue // all=false
			}
			if r.URL.Query().Get("filters") == enrolledFilter && c.labels[`river3.enroll`] != "true" {
				continue
			}
			rows = append(rows, map[string]any{"Id": id, "Names": []string{"/" + c.name}, "State": c.status, "Labels": c.labels})
		}
		_ = json.NewEncoder(w).Encode(rows)
	})
	mutate := func(verb, from, to string, conflict string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			defer e.mu.Unlock()
			c, ok := e.containers[r.PathValue("id")]
			if !ok {
				http.Error(w, `{"message":"No such container"}`, 404)
				return
			}
			if verb == "stop" && r.URL.Query().Get("t") != "10" {
				http.Error(w, `{"message":"bad t"}`, 400)
				return
			}
			if c.status == to {
				if verb == "stop" {
					w.WriteHeader(304)
				} else {
					http.Error(w, conflict, 409)
				}
				return
			}
			if c.status != from && verb != "stop" {
				http.Error(w, conflict, 409)
				return
			}
			c.status = to
			w.WriteHeader(204)
		}
	}
	mux.HandleFunc("POST /v1.43/containers/{id}/pause", mutate("pause", "running", "paused", `{"message":"is already paused"}`))
	mux.HandleFunc("POST /v1.43/containers/{id}/unpause", mutate("unpause", "paused", "running", `{"message":"is not paused"}`))
	mux.HandleFunc("POST /v1.43/containers/{id}/stop", mutate("stop", "running", "exited", ""))
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return e, sock
}

func (e *fakeEngine) add(id, status, startedAt string, labels map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.containers[id] = &fakeContainer{status: status, startedAt: startedAt, name: "c-" + id[:6], labels: labels}
}

func TestDockerAgainstFakeSocket(t *testing.T) {
	e, sock := newFakeEngine(t)
	d, err := NewDocker(sock)
	if err != nil {
		t.Fatal(err)
	}
	cid := strings.Repeat("1", 64)
	e.add(cid, "running", "2026-10-21T18:19:34.775655768Z", nil)
	ctx := context.Background()

	info, err := d.Inspect(ctx, cid)
	if err != nil || info.Status != Running || info.ContainerID != cid || info.Generation != "2026-10-21T18:19:34.775655768Z" {
		t.Fatalf("%+v %v", info, err)
	}
	if err := d.Pause(ctx, cid); err != nil {
		t.Fatal(err)
	}
	if info, _ = d.Inspect(ctx, cid); info.Status != Paused {
		t.Fatal(info)
	}
	// A second pause is 409 at the daemon: an adapter error, which the controller
	// records as evidence and then decides from Inspect.
	if err := d.Pause(ctx, cid); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("second pause: %v", err)
	}
	if err := d.Resume(ctx, cid); err != nil {
		t.Fatal(err)
	}
	if err := d.Terminate(ctx, cid); err != nil {
		t.Fatal(err)
	}
	if info, _ = d.Inspect(ctx, cid); info.Status != Exited {
		t.Fatal(info)
	}
	if err := d.Terminate(ctx, cid); err != nil { // 304 = already stopped = success
		t.Fatalf("stop of a stopped container: %v", err)
	}
	if info, err = d.Inspect(ctx, strings.Repeat("2", 64)); err != nil || info.Status != Missing {
		t.Fatalf("%+v %v", info, err)
	}
	if err := d.Pause(ctx, strings.Repeat("2", 64)); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("pause of a missing container: %v", err)
	}
	for _, bad := range []string{"c-111111", "111111111111", strings.Repeat("F", 64), strings.Repeat("1", 63)} {
		if err := d.Pause(ctx, bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
		if _, err := d.Inspect(ctx, bad); err == nil {
			t.Fatalf("inspected %q", bad)
		}
	}
	if _, err := NewDocker("relative.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
}

func TestDockerStatusMapping(t *testing.T) {
	e, sock := newFakeEngine(t)
	d, _ := NewDocker(sock)
	i := 0
	for status, want := range map[string]Status{"running": Running, "paused": Paused, "exited": Exited, "dead": Exited,
		"restarting": Unknown, "created": Unknown, "removing": Unknown} {
		i++
		cid := strings.Repeat(fmt.Sprintf("%x", i), 64)
		e.add(cid, status, "2026-10-21T00:00:00Z", nil)
		info, err := d.Inspect(context.Background(), cid)
		if err != nil || info.Status != want {
			t.Errorf("%s → %s (%v), want %s", status, info.Status, err, want)
		}
	}
}

func TestDockerListEnrolledUsesFilterAndInspectGeneration(t *testing.T) {
	e, sock := newFakeEngine(t)
	d, _ := NewDocker(sock)
	a, b, c, x := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("e", 64)
	e.add(a, "running", "2026-10-21T01:00:00Z", map[string]string{"river3.enroll": "true", "river3.asset_id": "w-a"})
	e.add(b, "paused", "2026-10-21T02:00:00Z", map[string]string{"river3.enroll": "true", "river3.asset_id": "w-b"})
	e.add(c, "exited", "2026-10-21T03:00:00Z", map[string]string{"river3.enroll": "true", "river3.asset_id": "w-c"})
	e.add(x, "running", "2026-10-21T04:00:00Z", map[string]string{"app": "unrelated"})

	got, err := d.ListEnrolled(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.lastList, "all=false") || !strings.Contains(e.lastList, "filters=") {
		t.Fatalf("list query %q", e.lastList)
	}
	byID := map[string]string{}
	for _, c := range got {
		byID[c.ID] = c.Generation
	}
	if len(got) != 2 || byID[a] != "2026-10-21T01:00:00Z" || byID[b] != "2026-10-21T02:00:00Z" {
		t.Fatalf("listed %+v", got)
	}
	for _, c := range got {
		if c.Labels["river3.enroll"] != "true" || !strings.HasPrefix(c.Name, "/c-") {
			t.Fatalf("%+v", c)
		}
	}
}
