package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	policy "river3.local/policy"
)

func good() File {
	return File{
		Node:    Node{TenantID: "lab", HostID: "node-a"},
		Sensors: []Sensor{{Name: "s1", TokenSHA256: strings.Repeat("ab", 32), ResolvesPaths: true}},
		Workloads: []Workload{{AssetID: "w1", Name: "W", Profile: "p", Kind: "ai_worker", ContainerID: strings.Repeat("a", 64),
			Generation: "g1", Dedicated: true, Active: true, PermittedActions: []policy.Action{policy.Pause}}},
	}
}

func TestLoadsFixture(t *testing.T) {
	r, err := Load(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate("dev-sensor-token"); !ok {
		t.Fatal("fixture token should authenticate")
	}
	if _, ok := r.Authenticate("dev-sensor-tokeN"); ok {
		t.Fatal("wrong token accepted")
	}
	w, ok := r.ByContainer(strings.Repeat("a", 64))
	if !ok || w.AssetID != "worker-01" {
		t.Fatal(w)
	}
	id := r.Identity(w)
	if id.TenantID != "lab" || id.HostID != "podman-vm" || id.ContainerID != w.ContainerID {
		t.Fatalf("%+v", id)
	}
}

func TestRejectsInvalidFiles(t *testing.T) {
	cases := map[string]func(*File){
		"plain token":            func(f *File) { f.Sensors[0].TokenSHA256 = "dev-sensor-token" },
		"short container id":     func(f *File) { f.Workloads[0].ContainerID = "abc123" },
		"no generation":          func(f *File) { f.Workloads[0].Generation = "" },
		"bad kind":               func(f *File) { f.Workloads[0].Kind = "unknown" },
		"shared dedicated":       func(f *File) { f.Workloads[0].Kind = "shared_service"; f.Workloads[0].Dedicated = true },
		"pause on shared":        func(f *File) { f.Workloads[0].Kind, f.Workloads[0].Dedicated = "shared_service", false },
		"alert as permitted":     func(f *File) { f.Workloads[0].PermittedActions = []policy.Action{policy.Alert} },
		"no sensors":             func(f *File) { f.Sensors = nil },
		"no tenant":              func(f *File) { f.Node.TenantID = "" },
		"duplicate asset":        func(f *File) { f.Workloads = append(f.Workloads, f.Workloads[0]) },
		"duplicate container id": func(f *File) { w := f.Workloads[0]; w.AssetID = "w2"; f.Workloads = append(f.Workloads, w) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := good()
			mutate(&f)
			if _, err := New(f); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := New(good()); err != nil {
		t.Fatal(err)
	}
}

func TestStrictJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.json")
	_ = os.WriteFile(p, []byte(`{"node":{"tenant_id":"lab","host_id":"h"},"sensors":[{"name":"s","token_sha256":"`+strings.Repeat("ab", 32)+`"}],"workloads":[],"identity_verified":true}`), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown field accepted: %v", err)
	}
}
