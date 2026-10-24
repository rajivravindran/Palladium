package adapter

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Live tests against the host's Docker daemon. They run only when the socket exists
// and the docker CLI (used purely to create and remove the test container) works;
// the adapter itself never shells out. The image must be present locally: there is
// no registry access in the sandbox these were written in.

const liveSocket = "/var/run/docker.sock"
const liveImage = "river3-lab-base:latest"

// dockerRun starts a labelled container and registers its removal. Returns the full id.
func dockerRun(t *testing.T, labels map[string]string, args ...string) string {
	t.Helper()
	cmd := []string{"run", "-d"}
	for k, v := range labels {
		cmd = append(cmd, "--label", k+"="+v)
	}
	cmd = append(cmd, args...)
	out, err := exec.Command("docker", cmd...).CombinedOutput()
	if err != nil {
		t.Skipf("docker run failed (daemon up but unusable?): %v: %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	if len(id) != 64 {
		t.Fatalf("docker run returned %q", id)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	return id
}

func requireLiveDocker(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(liveSocket); err != nil {
		t.Skipf("no docker socket at %s", liveSocket)
	}
	if err := exec.Command("docker", "image", "inspect", liveImage).Run(); err != nil {
		t.Skipf("image %s not present locally", liveImage)
	}
}

func TestLiveDockerPauseInspectUnpauseStopMissing(t *testing.T) {
	requireLiveDocker(t)
	d, err := NewDocker(liveSocket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	id := dockerRun(t, map[string]string{"river3.enroll": "true", "river3.asset_id": "live-adapter-01",
		"river3.profile": "diagnostic-worker", "river3.kind": "ai_worker"}, liveImage, "sleep", "300")

	info, err := d.Inspect(ctx, id)
	if err != nil || info.Status != Running || info.ContainerID != id {
		t.Fatalf("inspect after run: %+v %v", info, err)
	}
	gen := info.Generation
	if !strings.HasPrefix(gen, "20") || !strings.HasSuffix(gen, "Z") {
		t.Fatalf("generation should be State.StartedAt (RFC3339), got %q", gen)
	}

	if err := d.Pause(ctx, id); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if info, err = d.Inspect(ctx, id); err != nil || info.Status != Paused || info.Generation != gen {
		t.Fatalf("inspect after pause: %+v %v", info, err)
	}
	// The daemon's own view agrees (the adapter is not grading its own homework).
	if out, _ := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", id).Output(); strings.TrimSpace(string(out)) != "paused" {
		t.Fatalf("docker inspect says %q after adapter pause", out)
	}
	if err := d.Pause(ctx, id); err == nil {
		t.Fatal("second pause should be a 409 from the daemon")
	}

	if err := d.Resume(ctx, id); err != nil {
		t.Fatalf("unpause: %v", err)
	}
	if info, err = d.Inspect(ctx, id); err != nil || info.Status != Running || info.Generation != gen {
		t.Fatalf("inspect after unpause: %+v %v", info, err)
	}

	start := time.Now()
	if err := d.Terminate(ctx, id); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if info, err = d.Inspect(ctx, id); err != nil || info.Status != Exited {
		t.Fatalf("inspect after stop: %+v %v (took %s)", info, err, time.Since(start))
	}
	if err := d.Terminate(ctx, id); err != nil {
		t.Fatalf("stop of a stopped container should be 304 = ok: %v", err)
	}

	if out, err := exec.Command("docker", "rm", "-f", id).CombinedOutput(); err != nil {
		t.Fatalf("rm: %v %s", err, out)
	}
	if info, err = d.Inspect(ctx, id); err != nil || info.Status != Missing || info.ContainerID != id {
		t.Fatalf("inspect after rm: %+v %v", info, err)
	}
	t.Logf("live docker: run → pause → unpause → stop → rm verified through the adapter; generation %s", gen)
}

func TestLiveDockerListEnrolledSeesOnlyLabelledRunningContainers(t *testing.T) {
	requireLiveDocker(t)
	d, _ := NewDocker(liveSocket)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	labelled := dockerRun(t, map[string]string{"river3.enroll": "true", "river3.asset_id": "live-list-01",
		"river3.profile": "diagnostic-worker", "river3.kind": "ai_worker"}, liveImage, "sleep", "300")
	plain := dockerRun(t, map[string]string{"river3.enroll": "false"}, liveImage, "sleep", "300")

	got, err := d.ListEnrolled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, c := range got {
		if c.ID == plain {
			t.Fatalf("unlabelled container listed: %+v", c)
		}
		if c.ID == labelled {
			seen = true
			info, _ := d.Inspect(ctx, labelled)
			if c.Generation != info.Generation || c.Labels["river3.asset_id"] != "live-list-01" || !strings.HasPrefix(c.Name, "/") {
				t.Fatalf("listed entry %+v vs inspect %+v", c, info)
			}
		}
	}
	if !seen {
		t.Fatalf("labelled container not listed: %+v", got)
	}
}
