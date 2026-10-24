package controller

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// Live: discovery and containment against the host's Docker daemon. Skipped when the
// socket or the local lab image is absent. The docker CLI is used only to create,
// restart and remove the test containers; everything the controller does goes
// through adapter.Docker.

const (
	liveSocket = "/var/run/docker.sock"
	liveImage  = "river3-lab-base:latest"
)

func requireLiveDocker(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(liveSocket); err != nil {
		t.Skipf("no docker socket at %s", liveSocket)
	}
	if err := exec.Command("docker", "image", "inspect", liveImage).Run(); err != nil {
		t.Skipf("image %s not present locally", liveImage)
	}
}

func dockerRun(t *testing.T, labels map[string]string) string {
	t.Helper()
	args := []string{"run", "-d"}
	for k, v := range labels {
		args = append(args, "--label", k+"="+v)
	}
	args = append(args, liveImage, "sleep", "300")
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Skipf("docker run failed: %v: %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	return id
}

func TestLiveDockerDiscoveryEnrolsPausesRestartsAndRemoves(t *testing.T) {
	requireLiveDocker(t)
	dock, err := adapter.NewDocker(liveSocket)
	if err != nil {
		t.Fatal(err)
	}
	base := baseFile(t)
	empty, err := registry.New(base)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, withRegistry(empty), withAdapter(dock))
	r.now = time.Now().UTC() // real runtime, real clock: the candidate lease is measured against it
	d := &Discovery{Source: dock, Base: base}

	worker := dockerRun(t, map[string]string{"river3.enroll": "true", "river3.asset_id": "live-worker-01",
		"river3.profile": "diagnostic-worker", "river3.kind": "ai_worker", "river3.team": "lab"})
	shared := dockerRun(t, map[string]string{"river3.enroll": "true", "river3.asset_id": "live-payments-01",
		"river3.profile": "payment-service", "river3.kind": "shared_service", "river3.name": "Payments (live)"})
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	reg := r.c.Registry().Get()
	w, ok := reg.Workload("live-worker-01")
	if !ok || w.ContainerID != worker || !w.Dedicated || w.Team != "lab" || len(w.PermittedActions) != 1 {
		t.Fatalf("worker not enrolled from labels: %+v %v", w, ok)
	}
	s, ok := reg.Workload("live-payments-01")
	if !ok || s.ContainerID != shared || s.Dedicated || s.Name != "Payments (live)" || len(s.PermittedActions) != 0 {
		t.Fatalf("shared service not enrolled from labels: %+v %v", s, ok)
	}
	info, _ := dock.Inspect(context.Background(), worker)
	if w.Generation != info.Generation || !strings.HasSuffix(w.Generation, "Z") {
		t.Fatalf("generation %q must equal the runtime's StartedAt %q", w.Generation, info.Generation)
	}
	gen1 := w.Generation

	// The full loop on a real container: decoy read → VIOLATION → pause → VERIFIED by inspect.
	ev := func(id string) normalize.Envelope {
		return normalize.Envelope{
			Raw: normalize.Raw{Facts: normalize.RawFacts{ID: id, Sensor: "lab-sensor", Kind: "file_open", Outcome: "success",
				Workload: normalize.RawWorkload{ID: "live-worker-01", ContainerID: worker},
				Process:  normalize.RawProcess{PID: 1, Comm: "sleep"}, Target: decoyOpen(id)}},
			Sensor: r.sensor(), Authentic: true, ReceivedAt: r.now, Provenance: policy.Live,
		}
	}
	out := r.handle(ev("live-1"))
	mustState(t, out, journal.Verified)
	if o, _ := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", worker).Output(); strings.TrimSpace(string(o)) != "paused" {
		t.Fatalf("daemon says %q after a VERIFIED pause", o)
	}
	if p, ok := r.api.lastPatch(); !ok || p.Body.Status != "contained" || p.Body.WorkloadState != "frozen" {
		t.Fatalf("response not reported: %+v", p)
	}
	// A violation on the paused worker alerts only (not Active), the same as with the mock.
	if out2 := r.handle(ev("live-2")); out2.Candidate || out2.Status != policy.Violation {
		t.Fatalf("second violation on a paused container: %+v", out2)
	}

	// Operator resume through the same adapter.
	req := resumeReq("live-act-1")
	req.WorkloadID = "live-worker-01"
	if res := r.c.HandleOperatorAction(context.Background(), req, "test"); res != OpCompleted {
		t.Fatalf("resume: %s", res)
	}
	if info, _ = dock.Inspect(context.Background(), worker); info.Status != adapter.Running {
		t.Fatalf("after resume: %+v", info)
	}

	// Restart: new StartedAt. Until discovery runs, identity does not verify (alert only)...
	time.Sleep(1100 * time.Millisecond) // StartedAt has ns resolution, but make the change unmistakable
	if o, err := exec.Command("docker", "restart", "-t", "1", worker).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, o)
	}
	out3 := r.handle(ev("live-3"))
	if out3.Candidate || !containsPrefix(out3.Notes, "runtime generation differs") {
		t.Fatalf("stale enrollment must not act: %+v", out3)
	}
	// ...and after it runs, the new generation is enrolled and the worker is a target again.
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	w2, _ := r.c.Registry().Get().Workload("live-worker-01")
	if w2.Generation == gen1 || w2.ContainerID != worker {
		t.Fatalf("restart not followed: before %q after %q", gen1, w2.Generation)
	}
	mustState(t, r.handle(ev("live-4")), journal.Verified)
	_ = dock.Resume(context.Background(), worker)

	// Removal: the shared service disappears from the registry.
	if o, err := exec.Command("docker", "rm", "-f", shared).CombinedOutput(); err != nil {
		t.Fatalf("rm: %v %s", err, o)
	}
	if err := r.c.DiscoverOnce(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.Registry().Get().Workload("live-payments-01"); ok {
		t.Fatal("removed container still enrolled")
	}
	if _, ok := r.c.Registry().Get().Workload("live-worker-01"); !ok {
		t.Fatal("worker lost")
	}
	t.Logf("live docker discovery: enrolled 2 from labels, paused %s (gen %s) VERIFIED, resumed, restart → gen %s, rm → removed",
		worker[:12], gen1, w2.Generation)
}
