package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

const (
	cidB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cidC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// fakeEngine serves the two Engine/libpod API calls the sensor uses, over a unix
// socket, recording the paths it was asked for.
func fakeEngine(t *testing.T) (socket string, paths *[]string) {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes; TempDir can be long.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	socket = filepath.Join(dir, "e.sock")
	if len(socket) > 100 {
		socket = filepath.Join("/tmp", filepath.Base(dir)+".sock")
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	paths = &seen
	containers := map[string]map[string]any{
		cidA: {"Id": cidA, "State": map[string]any{"Status": "running", "Pid": 1001}},
		cidB: {"Id": cidB, "State": map[string]any{"Status": "running", "Pid": 1002}},
		cidC: {"Id": cidC, "State": map[string]any{"Status": "exited", "Pid": 0}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
		p := r.URL.Path
		p = strings.TrimPrefix(p, "/v4.0.0/libpod")
		switch {
		case p == "/containers/json":
			if !strings.Contains(r.URL.Query().Get("filters"), labelEnroll+"=true") {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": cidA, "Names": []string{"/worker-a"}, "State": "running", "Labels": map[string]string{
					labelEnroll: "true", labelAssetID: "worker-a", labelProfile: "diagnostic-worker", labelKind: "ai_worker", labelTeam: "payments"}},
				{"Id": cidB, "Names": []string{"/svc-b"}, "State": "running", "Labels": map[string]string{
					labelEnroll: "true", labelAssetID: "svc-b", labelProfile: "payment-service", labelKind: "shared_service", labelName: "Payments"}},
				{"Id": cidC, "Names": []string{"/old"}, "State": "exited", "Labels": map[string]string{
					labelEnroll: "true", labelAssetID: "old", labelProfile: "p", labelKind: "ai_worker"}},
				{"Id": "dddddddddddd", "Names": []string{"/short"}, "State": "running", "Labels": map[string]string{labelEnroll: "true"}},
			})
		case strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")
			c, ok := containers[id]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(c)
		default:
			w.WriteHeader(404)
		}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket, paths
}

func TestRuntimeClientDockerListAndPID(t *testing.T) {
	socket, paths := fakeEngine(t)
	rt, err := newRuntimeClient("docker", socket)
	if err != nil {
		t.Fatal(err)
	}
	list, err := rt.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != cidA || list[1].ID != cidB {
		t.Fatalf("exited and short-id containers must be dropped: %+v", list)
	}
	pid, err := rt.PID(context.Background(), cidA)
	if err != nil || pid != 1001 {
		t.Fatal(pid, err)
	}
	if _, err := rt.PID(context.Background(), cidC); !errors.Is(err, errNotRunning) {
		t.Fatalf("exited container: %v", err)
	}
	if _, err := rt.PID(context.Background(), strings.Repeat("e", 64)); !errors.Is(err, errNotRunning) {
		t.Fatalf("unknown container: %v", err)
	}
	if _, err := rt.PID(context.Background(), "aaaaaaaaaaaa"); err == nil {
		t.Fatal("short id accepted")
	}
	for _, p := range *paths {
		if strings.HasPrefix(p, "/v4.0.0") {
			t.Fatalf("docker client used the libpod prefix: %s", p)
		}
	}
}

func TestRuntimeClientPodmanPrefix(t *testing.T) {
	socket, paths := fakeEngine(t)
	rt, err := newRuntimeClient("podman", socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pid, err := rt.PID(context.Background(), cidB); err != nil || pid != 1002 {
		t.Fatal(pid, err)
	}
	for _, p := range *paths {
		if !strings.HasPrefix(p, "/v4.0.0/libpod/containers/") {
			t.Fatalf("podman client must use the libpod routes: %s", p)
		}
	}
	if _, err := newRuntimeClient("containerd", "/x"); err == nil {
		t.Fatal("unknown runtime accepted")
	}
	if _, err := newRuntimeClient("docker", "relative.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
}

func TestEnrollmentFromLabels(t *testing.T) {
	good := containerSummary{ID: cidA, Names: []string{"/worker-a"}, Labels: map[string]string{
		labelEnroll: "true", labelAssetID: "worker-a", labelProfile: "diagnostic-worker", labelKind: "ai_worker", labelTeam: "payments",
		"river3.dedicated": "true", "river3.actions": "PAUSE_CONTAINER"}}
	en, err := enrollmentFromLabels(good)
	if err != nil {
		t.Fatal(err)
	}
	if en.AssetID != "worker-a" || en.Name != "worker-a" || en.Profile != "diagnostic-worker" || en.Kind != "ai_worker" || en.Team != "payments" || en.ContainerID != cidA {
		t.Fatalf("%+v", en)
	}
	with := func(k, v string) containerSummary {
		c := good
		c.Labels = map[string]string{}
		for kk, vv := range good.Labels {
			c.Labels[kk] = vv
		}
		if v == "" {
			delete(c.Labels, k)
		} else {
			c.Labels[k] = v
		}
		return c
	}
	named, _ := enrollmentFromLabels(with(labelName, "Worker A"))
	if named.Name != "Worker A" {
		t.Fatal(named.Name)
	}
	for name, c := range map[string]containerSummary{
		"not enrolled":  with(labelEnroll, "yes"),
		"no asset":      with(labelAssetID, ""),
		"bad asset":     with(labelAssetID, "has space"),
		"no profile":    with(labelProfile, ""),
		"bad kind":      with(labelKind, "robot"),
		"team too long": with(labelTeam, strings.Repeat("t", 65)),
	} {
		if _, err := enrollmentFromLabels(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDiscoverEnrollmentsReportsBadLabelsAndContinues(t *testing.T) {
	socket, _ := fakeEngine(t)
	rt, _ := newRuntimeClient("docker", socket)
	list, problems, err := discoverEnrollments(context.Background(), rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].AssetID != "worker-a" || list[1].AssetID != "svc-b" || list[1].Name != "Payments" || len(problems) != 0 {
		t.Fatalf("%+v %v", list, problems)
	}
}

func TestMergeEnrollmentsFileWins(t *testing.T) {
	file := []Enrollment{
		{AssetID: "worker-a", Name: "From file", Profile: "file-profile", Kind: "ai_worker", ContainerID: cidA},
		{AssetID: "pinned", Name: "P", Profile: "p", Kind: "ai_worker", ContainerID: cidB},
	}
	discovered := []Enrollment{
		{AssetID: "worker-a", Name: "From label", Profile: "label-profile", Kind: "ai_worker", ContainerID: cidC}, // same asset: dropped
		{AssetID: "svc-b", Name: "S", Profile: "p", Kind: "shared_service", ContainerID: cidB},                    // same container: dropped
		{AssetID: "new", Name: "N", Profile: "p", Kind: "ai_worker", ContainerID: cidC},                           // kept
		{AssetID: "new", Name: "N2", Profile: "p", Kind: "ai_worker", ContainerID: strings.Repeat("f", 64)},       // duplicate label asset: dropped
	}
	out, conflicts := mergeEnrollments(file, discovered)
	if len(out) != 3 || out[0].Profile != "file-profile" || out[2].AssetID != "new" || out[2].Name != "N" {
		t.Fatalf("%+v", out)
	}
	if len(conflicts) != 3 {
		t.Fatalf("%v", conflicts)
	}
}

func TestEnrollerDiscoveryMergesRegistersAndSurvivesOutage(t *testing.T) {
	var found []Enrollment
	var fail error
	var registered []Enrollment
	var applied map[uint32]bool
	e := &Enroller{
		Enrollments: []Enrollment{{AssetID: "file-1", Name: "F", Profile: "p", Kind: "ai_worker", Mntns: 11}},
		Discover: func(context.Context) ([]Enrollment, []string, error) {
			return found, nil, fail
		},
		Watch:      newWatchlist(),
		SetWatched: func(d map[uint32]bool) error { applied = d; return nil },
		Log:        func(string, ...any) {},
		OnEnrolled: func(en Enrollment) { registered = append(registered, en) },
	}
	found = []Enrollment{{AssetID: "label-1", Name: "L", Profile: "p", Kind: "ai_worker", Team: "payments", Mntns: 22}}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !applied[11] || !applied[22] || len(applied) != 2 {
		t.Fatalf("%v", applied)
	}
	if ref, _ := e.Watch.Lookup(22); ref.Team != "payments" || ref.ID != "label-1" {
		t.Fatalf("%+v", ref)
	}
	if len(registered) != 2 {
		t.Fatalf("registered %+v", registered)
	}
	// Runtime outage: the last discovery stands, nothing is unwatched, nothing re-registered.
	fail = errors.New("socket gone")
	_ = e.Refresh(context.Background())
	if !applied[22] || len(registered) != 2 {
		t.Fatalf("outage dropped the label enrollment: %v %d", applied, len(registered))
	}
	// Container gone from the runtime: unwatched. A changed profile re-registers.
	fail = nil
	found = []Enrollment{{AssetID: "label-1", Name: "L", Profile: "p2", Kind: "ai_worker", Team: "payments", Mntns: 22}}
	_ = e.Refresh(context.Background())
	if len(registered) != 3 || registered[2].Profile != "p2" {
		t.Fatalf("%+v", registered)
	}
	found = nil
	_ = e.Refresh(context.Background())
	if applied[22] || !applied[11] {
		t.Fatalf("%v", applied)
	}
}

func TestEnrollerWithoutRuntimeIsSilentAboutContainerIDs(t *testing.T) {
	// The Falco source identifies by container id; it must not log "no resolver"
	// on every refresh (the old podman-for-falco bug).
	var logs []string
	e := &Enroller{
		Enrollments: []Enrollment{{AssetID: "w", Name: "W", Profile: "p", Kind: "ai_worker", ContainerID: cidA}},
		Watch:       newWatchlist(),
		Log:         func(f string, a ...any) { logs = append(logs, f) },
	}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 {
		t.Fatalf("%v", logs)
	}
	if _, ok := e.Watch.LookupContainer(cidA); !ok {
		t.Fatal("container id must still be resolvable")
	}
}

func TestEnrollmentFileAcceptsTeam(t *testing.T) {
	p := writeEnroll(t, `[{"asset_id":"w","name":"W","profile":"p","kind":"ai_worker","container_id":"`+cidA+`","team":"payments"}]`)
	list, err := loadEnrollments(p)
	if err != nil || list[0].Team != "payments" {
		t.Fatal(err)
	}
}
