//go:build linux && amd64

package main

// Live tests: they need root, and for the container ones a Docker daemon with the
// local image river3-lab-base:latest. Every test skips with the reason when a
// prerequisite is missing, so `go test ./...` stays green on a laptop.
//
// What they prove, and where:
//   - the generated object loads and the tracepoints attach (TestLiveTracepointSource)
//   - the LSM family loads and attaches, OR the kernel refuses it and the error is
//     the one the fallback keys on (TestLiveLSMSourceOrUnavailable)
//   - blocked_inodes accepts the Go key type and the sync is exact (TestLiveBlockedInodesMapSync)
//   - labelled containers are discovered and watched by mount namespace, an
//     unlabelled one is not (TestLiveDiscoveryByLabels)
//   - the whole binary, -source lsm with label discovery against docker, sees a
//     docker exec of python3, its connect and a decoy read; inline when the kernel
//     allows LSM programs, through the documented fallback otherwise
//     (TestLiveSensorSeesDockerExec)
//   - -block-decoys denies the decoy read with EPERM and emits outcome "blocked"
//     (TestLiveBlockDecoys; skipped where LSM programs cannot load)

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestBPFLSMActiveParsing(t *testing.T) {
	if a, u := bpfLSMActive([]byte("lockdown,capability,landlock,selinux,bpf\n"), nil); !a || u {
		t.Fatal("bpf listed but not reported active")
	}
	if a, u := bpfLSMActive([]byte("lockdown,capability,apparmor\n"), nil); a || u {
		t.Fatal("bpf missing but reported active")
	}
	if a, u := bpfLSMActive(nil, errors.New("securityfs not mounted")); a || !u {
		t.Fatal("unreadable listing must be reported unknown, not inactive")
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestLiveTracepointSource(t *testing.T) {
	requireRoot(t)
	if _, err := os.Stat("/sys/kernel/tracing/events"); err != nil {
		t.Skipf("tracefs not mounted: %v", err)
	}
	src, err := openEBPF(modeTracepoint)
	if err != nil {
		t.Fatalf("tracepoint source: %v", err)
	}
	defer src.Close()
	if err := src.setWatched(map[uint32]bool{1: true, 2: true}); err != nil {
		t.Fatal(err)
	}
	if err := src.setWatched(map[uint32]bool{2: true}); err != nil {
		t.Fatal(err)
	}
	var k uint32
	var v uint8
	n := 0
	it := src.watched.Iterate()
	for it.Next(&k, &v) {
		n++
		if k != 2 {
			t.Fatalf("stale key %d", k)
		}
	}
	if n != 1 {
		t.Fatalf("%d keys", n)
	}
	if err := src.setBlocked(nil); err == nil {
		t.Fatal("tracepoint source must refuse inline blocking")
	}
}

// lsmAvailable loads the LSM family once; the result decides which live tests run.
func lsmAvailable(t *testing.T) (ok bool, reason string) {
	t.Helper()
	requireRoot(t)
	src, err := openEBPF(modeLSM)
	if err != nil {
		if errors.Is(err, errNoBPFLSM) {
			return false, err.Error()
		}
		t.Fatalf("LSM source failed for a reason other than kernel support: %v", err)
	}
	src.Close()
	return true, ""
}

func TestLiveLSMSourceOrUnavailable(t *testing.T) {
	ok, reason := lsmAvailable(t)
	if !ok {
		t.Skipf("LSM family not loadable here, fallback error is correct: %s", reason)
	}
	src, err := openEBPF(modeLSM)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if src.Mode() != modeLSM || src.blocked == nil || len(src.links) != 3 {
		t.Fatalf("mode=%s blocked=%v links=%d", src.Mode(), src.blocked != nil, len(src.links))
	}
}

func TestLiveBlockedInodesMapSync(t *testing.T) {
	requireRoot(t)
	spec, err := loadSensor()
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Blocked *ebpf.Map `ebpf:"blocked_inodes"`
	}
	if err := spec.LoadAndAssign(&o, nil); err != nil {
		t.Skipf("cannot create BPF maps here: %v", err)
	}
	defer o.Blocked.Close()
	s := &ebpfSource{mode: modeLSM, blocked: o.Blocked}
	a := inodeKey{Dev: 0x800001, Ino: 4242, Mntns: 4026532001}
	b := inodeKey{Dev: 0x800001, Ino: 4242, Mntns: 4026532002} // same file, other workload
	c := inodeKey{Dev: 0x12c, Ino: 7, Mntns: 4026532001}
	if err := s.setBlocked(map[inodeKey]bool{a: true, b: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.setBlocked(map[inodeKey]bool{a: true, c: true}); err != nil {
		t.Fatal(err)
	}
	got := map[inodeKey]bool{}
	var k sensorInodeKey
	var v uint8
	it := o.Blocked.Iterate()
	for it.Next(&k, &v) {
		got[inodeKey{Dev: k.Dev, Ino: k.Ino, Mntns: k.Mntns}] = v == 1
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[a] || !got[c] || got[b] {
		t.Fatalf("%v", got)
	}
	if o.Blocked.KeySize() != 24 {
		t.Fatalf("key size %d: struct inode_key and sensorInodeKey disagree", o.Blocked.KeySize())
	}
}

// --- docker ------------------------------------------------------------------------

const liveImage = "river3-lab-base:latest"

// liveDocker checks the container prerequisites and removes leftovers of earlier runs.
func liveDocker(t *testing.T) {
	t.Helper()
	requireRoot(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker CLI")
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("no docker socket")
	}
	if out, err := exec.Command("docker", "image", "inspect", liveImage).CombinedOutput(); err != nil {
		t.Skipf("image %s not present: %s", liveImage, strings.TrimSpace(string(out)))
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=river3.test=live").Output(); len(strings.TrimSpace(string(out))) > 0 {
		args := append([]string{"rm", "-f"}, strings.Fields(string(out))...)
		_ = exec.Command("docker", args...).Run()
	}
}

// runContainer starts a lab container and registers its removal. Labelled ones
// carry the contract's labels; all carry river3.test=live for cleanup.
func runContainer(t *testing.T, asset string, labelled bool) (id string) {
	t.Helper()
	name := fmt.Sprintf("river3-live-%s-%04d", asset, rand.Intn(10000))
	args := []string{"run", "-d", "--name", name, "--label", "river3.test=live"}
	if labelled {
		args = append(args,
			"--label", "river3.enroll=true", "--label", "river3.asset_id="+asset,
			"--label", "river3.profile=diagnostic-worker", "--label", "river3.kind=ai_worker",
			"--label", "river3.team=lab", "--label", "river3.name=Live "+asset)
	}
	args = append(args, liveImage, "sh", "-c",
		"mkdir -p /opt/config && echo inert > /opt/config/.db_recovery_creds && echo plain > /tmp/plain.txt && exec sleep 300")
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	id = strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("docker", "exec", id, "sh", "-c", "test -f /opt/config/.db_recovery_creds").Run() == nil {
			return id
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container %s never wrote the decoy", name)
	return id
}

func containerMntns(t *testing.T, id string) uint32 {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", id).Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	ns, err := mntnsOf(uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func TestLiveDiscoveryByLabels(t *testing.T) {
	liveDocker(t)
	a := runContainer(t, "disc-a", true)
	b := runContainer(t, "disc-b", true)
	c := runContainer(t, "disc-c", false)
	rt, err := newRuntimeClient("docker", "/var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	var applied map[uint32]bool
	e := &Enroller{
		Discover:   func(ctx context.Context) ([]Enrollment, []string, error) { return discoverEnrollments(ctx, rt) },
		Runtime:    rt,
		Watch:      newWatchlist(),
		SetWatched: func(d map[uint32]bool) error { applied = d; return nil },
		Log:        t.Logf,
	}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	nsA, nsB, nsC := containerMntns(t, a), containerMntns(t, b), containerMntns(t, c)
	t.Logf("mntns: a=%d b=%d c=%d; watched=%v", nsA, nsB, nsC, applied)
	if !applied[nsA] || !applied[nsB] {
		t.Fatalf("labelled containers not watched: %v", applied)
	}
	if applied[nsC] {
		t.Fatalf("unlabelled container watched: %v", applied)
	}
	refA, ok := e.Watch.Lookup(nsA)
	if !ok || refA.ID != "disc-a" || refA.Team != "lab" || refA.Name != "Live disc-a" || refA.ContainerID != a || refA.Profile != "diagnostic-worker" {
		t.Fatalf("%+v", refA)
	}
	if _, ok := e.Watch.LookupContainer(c); ok {
		t.Fatal("unlabelled container must not be known at all")
	}
}

// --- the whole binary -----------------------------------------------------------------

var (
	sensorBinOnce sync.Once
	sensorBin     string
	sensorBinErr  error
)

// TestMain removes the binary buildSensor may have compiled.
func TestMain(m *testing.M) {
	code := m.Run()
	if sensorBin != "" {
		_ = os.RemoveAll(filepath.Dir(sensorBin))
	}
	os.Exit(code)
}

// buildSensor compiles river3d once per test run (the package directory is the cwd).
func buildSensor(t *testing.T) string {
	t.Helper()
	sensorBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "river3d-live")
		if err != nil {
			sensorBinErr = err
			return
		}
		sensorBin = dir + "/river3d"
		out, err := exec.Command("go", "build", "-o", sensorBin, ".").CombinedOutput()
		if err != nil {
			sensorBinErr = fmt.Errorf("go build: %v: %s", err, out)
		}
	})
	if sensorBinErr != nil {
		t.Fatal(sensorBinErr)
	}
	return sensorBin
}

// sensorRun is a running river3d with its stdout events and stderr log collected.
type sensorRun struct {
	cmd    *exec.Cmd
	mu     sync.Mutex
	events []Event
	stderr []string
	ready  chan string // the "sensor attached" line
}

func startSensor(t *testing.T, args ...string) *sensorRun {
	t.Helper()
	bin := buildSensor(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	r := &sensorRun{cmd: cmd, ready: make(chan string, 1)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			r.mu.Lock()
			t.Logf("sensor stderr:\n%s", strings.Join(r.stderr, "\n"))
			r.mu.Unlock()
		}
	})
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var ev Event
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				r.mu.Lock()
				r.events = append(r.events, ev)
				r.mu.Unlock()
			}
		}
	}()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			r.mu.Lock()
			r.stderr = append(r.stderr, line)
			r.mu.Unlock()
			if strings.Contains(line, "sensor attached") {
				select {
				case r.ready <- line:
				default:
				}
			}
		}
	}()
	return r
}

func (r *sensorRun) waitReady(t *testing.T) string {
	t.Helper()
	select {
	case line := <-r.ready:
		return line
	case <-time.After(30 * time.Second):
		r.mu.Lock()
		defer r.mu.Unlock()
		t.Fatalf("sensor did not attach:\n%s", strings.Join(r.stderr, "\n"))
		return ""
	}
}

func (r *sensorRun) logged(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.stderr {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// find waits for an event matching pred and returns it.
func (r *sensorRun) find(t *testing.T, what string, pred func(Event) bool) Event {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, ev := range r.events {
			if pred(ev) {
				r.mu.Unlock()
				return ev
			}
		}
		r.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var kinds []string
	for _, ev := range r.events {
		kinds = append(kinds, fmt.Sprintf("%s %s %s %s%s", ev.Facts.Workload.ID, ev.Facts.Kind, ev.Facts.Outcome, ev.Facts.Target.Path, ev.Facts.Target.Exe))
	}
	t.Fatalf("no event: %s (%d events seen)\n%s", what, len(r.events), strings.Join(kinds, "\n"))
	return Event{}
}

const pyConnect = `import socket
s = socket.socket()
s.setblocking(False)
try:
    s.connect(("127.0.0.1", 9))
except BlockingIOError:
    pass
`

func TestLiveSensorSeesDockerExec(t *testing.T) {
	liveDocker(t)
	if _, err := os.Stat("/sys/kernel/tracing/events"); err != nil {
		t.Skipf("tracefs not mounted: %v", err)
	}
	id := runContainer(t, "exec-a", true)
	_ = runContainer(t, "exec-unlabelled", false)
	r := startSensor(t, "-source", "lsm", "-enroll", "", "-enroll-from-labels", "-runtime", "docker",
		"-stdout", "-refresh", "1s", "-name", "live")
	line := r.waitReady(t)
	t.Logf("%s", line)
	inline := strings.Contains(line, "lsm sensor attached")
	if !inline && !r.logged("falling back to the tracepoint source") {
		t.Fatal("neither the LSM family nor the documented fallback")
	}

	out, err := exec.Command("docker", "exec", id, "python3", "-c", pyConnect).CombinedOutput()
	if err != nil {
		t.Fatalf("python3 in the container: %v: %s", err, out)
	}
	ex := r.find(t, "process_exec of python3", func(ev Event) bool {
		return ev.Facts.Workload.ID == "exec-a" && ev.Facts.Kind == KindProcessExec && strings.Contains(ev.Facts.Target.Exe, "python3")
	})
	t.Logf("exec: %s", mustJSON(t, ex))
	if ex.Facts.Target.BinaryClass != "INTERPRETER" || !ex.Facts.Target.PathResolved || ex.Facts.Inline != inline || ex.Facts.Workload.Team != "lab" {
		t.Fatalf("%+v", ex.Facts)
	}
	cn := r.find(t, "net_connect to 127.0.0.1:9", func(ev Event) bool {
		return ev.Facts.Workload.ID == "exec-a" && ev.Facts.Kind == KindNetConnect && ev.Facts.Target.IP == "127.0.0.1" && ev.Facts.Target.Port == 9
	})
	t.Logf("connect: %s", mustJSON(t, cn))
	if inline && cn.Facts.Outcome != OutcomeSuccess {
		t.Fatalf("an allowed LSM connect is success whatever TCP does later: %+v", cn.Facts)
	}
	if !inline && cn.Facts.Outcome != OutcomePending && cn.Facts.Outcome != OutcomeFailed && cn.Facts.Outcome != OutcomeSuccess {
		t.Fatalf("%+v", cn.Facts)
	}

	if out, err := exec.Command("docker", "exec", id, "cat", "/opt/config/.db_recovery_creds").CombinedOutput(); err != nil || !strings.Contains(string(out), "inert") {
		t.Fatalf("without -block-decoys the decoy must be readable: %v: %s", err, out)
	}
	op := r.find(t, "file_open of the decoy", func(ev Event) bool {
		return ev.Facts.Workload.ID == "exec-a" && ev.Facts.Kind == KindFileOpen && ev.Facts.Target.Path == "/opt/config/.db_recovery_creds"
	})
	t.Logf("open: %s", mustJSON(t, op))
	// Only the inline path can vouch for the name: with tracepoints `cat` is often
	// gone before the userspace walk under /proc/<pid>/root, and the raw string
	// stays unvouched (path_resolved=false). That race is one reason -source lsm exists.
	if op.Facts.Outcome != OutcomeSuccess || op.Facts.Target.Access != "read" || (inline && !op.Facts.Target.PathResolved) {
		t.Fatalf("%+v", op.Facts)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.events {
		if ev.Facts.Workload.ID != "exec-a" {
			t.Fatalf("event for an unenrolled workload: %+v", ev.Facts.Workload)
		}
	}
}

func TestLiveBlockDecoys(t *testing.T) {
	liveDocker(t)
	if ok, reason := lsmAvailable(t); !ok {
		t.Skipf("inline blocking needs the LSM family: %s", reason)
	}
	if _, err := os.Stat("../policy/examples/profiles/diagnostic.json"); err != nil {
		t.Skip("policy example profiles not alongside")
	}
	id := runContainer(t, "block-a", true)
	r := startSensor(t, "-source", "lsm", "-block-decoys", "-shadow-profiles", "../policy/examples/profiles",
		"-enroll", "", "-enroll-from-labels", "-runtime", "docker", "-stdout", "-refresh", "1s", "-name", "live")
	line := r.waitReady(t)
	if !strings.Contains(line, "lsm sensor attached") || !strings.Contains(line, "block-decoys=true") {
		t.Fatalf("%s", line)
	}
	// The map is filled synchronously in the first refresh, before "attached".
	out, err := exec.Command("docker", "exec", id, "cat", "/opt/config/.db_recovery_creds").CombinedOutput()
	if err == nil || !strings.Contains(strings.ToLower(string(out)), "permission denied") {
		t.Fatalf("decoy read must fail with EPERM: err=%v out=%s", err, out)
	}
	blocked := r.find(t, "blocked decoy open", func(ev Event) bool {
		return ev.Facts.Workload.ID == "block-a" && ev.Facts.Kind == KindFileOpen && ev.Facts.Outcome == OutcomeBlocked
	})
	t.Logf("BLOCKED: %s", mustJSON(t, blocked))
	if blocked.Facts.Target.Path != "/opt/config/.db_recovery_creds" || !blocked.Facts.Inline || blocked.Facts.Errno != 1 || !blocked.Facts.Target.PathResolved {
		t.Fatalf("%+v", blocked.Facts)
	}
	out, err = exec.Command("docker", "exec", id, "cat", "/tmp/plain.txt").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "plain") {
		t.Fatalf("plain read must succeed: %v: %s", err, out)
	}
	plain := r.find(t, "allowed plain open", func(ev Event) bool {
		return ev.Facts.Workload.ID == "block-a" && ev.Facts.Kind == KindFileOpen && ev.Facts.Target.Path == "/tmp/plain.txt"
	})
	t.Logf("allowed: %s", mustJSON(t, plain))
	if plain.Facts.Outcome != OutcomeSuccess || !plain.Facts.Inline {
		t.Fatalf("%+v", plain.Facts)
	}
}

func TestLiveBlockDecoysRefusesWithoutLSM(t *testing.T) {
	liveDocker(t)
	if ok, _ := lsmAvailable(t); ok {
		t.Skip("LSM family available: the refusal path does not apply here")
	}
	if _, err := os.Stat("../policy/examples/profiles/diagnostic.json"); err != nil {
		t.Skip("policy example profiles not alongside")
	}
	bin := buildSensor(t)
	out, err := exec.Command(bin, "-source", "lsm", "-block-decoys", "-shadow-profiles", "../policy/examples/profiles",
		"-enroll", "", "-enroll-from-labels", "-runtime", "docker", "-stdout").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "inline blocking is impossible here") {
		t.Fatalf("must refuse to start rather than silently not enforce: err=%v\n%s", err, out)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}
