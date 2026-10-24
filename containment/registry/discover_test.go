package registry

import (
	"strings"
	"testing"

	policy "river3.local/policy"
)

func labelled(id, asset, kind string, extra map[string]string) Container {
	l := map[string]string{LabelEnroll: "true", LabelAssetID: asset, LabelProfile: "diagnostic-worker", LabelKind: kind}
	for k, v := range extra {
		l[k] = v
	}
	return Container{ID: strings.Repeat(id, 64), Name: "/" + asset + "-ctr", Labels: l, Generation: "2026-10-21T18:19:34.775655768Z"}
}

func TestWorkloadFromLabelsDefaults(t *testing.T) {
	w, err := WorkloadFromLabels(labelled("a", "worker-01", "ai_worker", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !w.Dedicated || !w.Active || w.Name != "worker-01-ctr" || len(w.PermittedActions) != 1 || w.PermittedActions[0] != policy.Pause {
		t.Fatalf("ai_worker defaults: %+v", w)
	}
	if w.Generation != "2026-10-21T18:19:34.775655768Z" || w.ContainerID != strings.Repeat("a", 64) {
		t.Fatalf("runtime facts not carried: %+v", w)
	}

	s, err := WorkloadFromLabels(labelled("b", "payments-01", "shared_service", map[string]string{LabelName: "Payments", LabelTeam: "fintech"}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Dedicated || len(s.PermittedActions) != 0 || s.Name != "Payments" || s.Team != "fintech" {
		t.Fatalf("shared_service defaults: %+v", s)
	}

	// Explicit labels override the defaults.
	e, err := WorkloadFromLabels(labelled("c", "worker-02", "ai_worker", map[string]string{LabelDedicated: "false", LabelActions: "REVOKE_SESSION, PAUSE_CONTAINER"}))
	if err != nil {
		t.Fatal(err)
	}
	if e.Dedicated || len(e.PermittedActions) != 2 {
		t.Fatalf("%+v", e)
	}
	if _, err := WorkloadFromLabels(labelled("d", "worker-03", "ai_worker", map[string]string{LabelActions: ""})); err != nil {
		t.Fatal("empty actions label should mean none, not an error")
	}
}

func TestWorkloadFromLabelsRefusals(t *testing.T) {
	cases := map[string]func(*Container){
		"not enrolled":     func(c *Container) { c.Labels[LabelEnroll] = "yes" },
		"bad asset id":     func(c *Container) { c.Labels[LabelAssetID] = "has space" },
		"no asset id":      func(c *Container) { delete(c.Labels, LabelAssetID) },
		"no profile":       func(c *Container) { delete(c.Labels, LabelProfile) },
		"bad kind":         func(c *Container) { c.Labels[LabelKind] = "sidecar" },
		"bad dedicated":    func(c *Container) { c.Labels[LabelDedicated] = "maybe" },
		"bad action":       func(c *Container) { c.Labels[LabelActions] = "KILL" },
		"alert as action":  func(c *Container) { c.Labels[LabelActions] = "ALERT" },
		"short id":         func(c *Container) { c.ID = "abc123" },
		"never started":    func(c *Container) { c.Generation = "" },
		"shared dedicated": func(c *Container) { c.Labels[LabelKind] = "shared_service"; c.Labels[LabelDedicated] = "true" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := labelled("a", "worker-01", "ai_worker", nil)
			mutate(&c)
			w, err := WorkloadFromLabels(c)
			if err == nil {
				// "shared dedicated" passes the label parser; the registry rules catch it.
				if _, err = New(File{Node: good().Node, Sensors: good().Sensors, Workloads: []Workload{w}}); err == nil {
					t.Fatalf("accepted: %+v", w)
				}
			}
		})
	}
}

func TestDiscoverBuildsSkipsAndDedupes(t *testing.T) {
	base := good()
	base.Workloads = []Workload{{AssetID: "stale-static-entry"}} // must be ignored, not merged
	known := func(p string) bool { return p == "diagnostic-worker" }
	containers := []Container{
		labelled("a", "worker-01", "ai_worker", nil),
		labelled("b", "payments-01", "shared_service", nil),
		labelled("c", "worker-01", "ai_worker", nil), // impersonates worker-01: both dropped
		labelled("d", "typo-01", "ai_worker", map[string]string{LabelProfile: "diagnostc-worker"}),
		labelled("e", "bad id!", "ai_worker", nil),
	}
	r, skipped, err := Discover(base, containers, known)
	if err != nil {
		t.Fatal(err)
	}
	ws := r.Workloads()
	if len(ws) != 1 || ws[0].AssetID != "payments-01" {
		t.Fatalf("enrolled %+v", ws)
	}
	if _, ok := r.Workload("stale-static-entry"); ok {
		t.Fatal("file workloads must be ignored with discovery on")
	}
	if len(skipped) != 4 {
		t.Fatalf("skipped %+v", skipped)
	}
	reasons := ""
	for _, s := range skipped {
		reasons += s.Reason + "|"
	}
	for _, want := range []string{`asset id "worker-01" is claimed by 2 containers`, `profile "diagnostc-worker" is not in the active policy set`, "not a valid identifier"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("missing skip reason %q in %q", want, reasons)
		}
	}
	if r.Node() != base.Node {
		t.Fatal("node must come from the file")
	}
	if _, ok := r.Authenticate("x"); ok {
		t.Fatal("sensor auth broken")
	}
}

func TestFingerprintAndDiffTrackRestarts(t *testing.T) {
	base := good()
	a := labelled("a", "worker-01", "ai_worker", nil)
	b := labelled("b", "payments-01", "shared_service", nil)
	r1, _, err := Discover(base, []Container{a, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	same, _, _ := Discover(base, []Container{b, a}, nil) // order must not matter
	if Fingerprint(r1) != Fingerprint(same) {
		t.Fatal("fingerprint depends on order")
	}
	a2 := a
	a2.Generation = "2026-10-21T19:00:00Z" // restarted
	r2, _, _ := Discover(base, []Container{a2}, nil)
	if Fingerprint(r1) == Fingerprint(r2) {
		t.Fatal("restart not visible in fingerprint")
	}
	d := DiffRegistries(r1, r2)
	if len(d.Restarted) != 1 || d.Restarted[0] != "worker-01" || len(d.Removed) != 1 || d.Removed[0] != "payments-01" || len(d.Added) != 0 {
		t.Fatalf("%+v", d)
	}
	if !DiffRegistries(r1, same).Empty() {
		t.Fatal("identical sets differ")
	}
	if d := DiffRegistries(nil, r1); len(d.Added) != 2 {
		t.Fatalf("%+v", d)
	}
}
