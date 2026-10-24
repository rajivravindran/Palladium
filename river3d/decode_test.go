package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cidA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fakeProc builds <tmp>/proc/4242/{root,cwd,exe} pointing into a fake container rootfs.
func fakeProc(t *testing.T) (procRoot string) {
	t.Helper()
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	for _, d := range []string{"opt/config", "etc/app", "usr/bin", "workspace", "var/log/app"} {
		if err := os.MkdirAll(filepath.Join(rootfs, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(rootfs, "opt/config/.db_recovery_creds"), []byte("inert"), 0o600)
	_ = os.WriteFile(filepath.Join(rootfs, "usr/bin/python3.12"), []byte("#!"), 0o755)
	_ = os.WriteFile(filepath.Join(rootfs, "var/log/app/error.log"), nil, 0o644)
	_ = os.Symlink("/opt/config/.db_recovery_creds", filepath.Join(rootfs, "etc/app/settings")) // absolute symlink inside the root
	_ = os.Symlink("python3.12", filepath.Join(rootfs, "usr/bin/python3"))
	_ = os.Symlink(filepath.Join(tmp, "outside.txt"), filepath.Join(rootfs, "etc/app/escape")) // points outside the root
	_ = os.WriteFile(filepath.Join(tmp, "outside.txt"), nil, 0o644)

	procRoot = filepath.Join(tmp, "proc")
	pd := filepath.Join(procRoot, "4242")
	_ = os.MkdirAll(pd, 0o755)
	_ = os.Symlink(rootfs, filepath.Join(pd, "root"))
	_ = os.Symlink("/workspace", filepath.Join(pd, "cwd")) // what readlink(/proc/pid/cwd) returns: a path in the process's view
	_ = os.Symlink(filepath.Join(rootfs, "usr/bin/python3.12"), filepath.Join(pd, "exe"))
	return procRoot
}

func testDecoder(t *testing.T) (*Decoder, *Watchlist) {
	t.Helper()
	w := newWatchlist()
	w.replace(map[uint32]WorkloadRef{4026532001: {ID: "worker-01", Name: "W", Profile: "diagnostic-worker", Kind: "ai_worker", Enrolled: true, ContainerID: cidA}},
		map[string]WorkloadRef{cidA: {ID: "worker-01", ContainerID: cidA, Enrolled: true}})
	boot := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	return &Decoder{Sensor: "ebpf", Watch: w, Clock: Clock{wallAtBoot: boot}, ProcRoot: fakeProc(t)}, w
}

func base(typ uint32) kernelEvent {
	return kernelEvent{EnterNs: 1_000_000_000, ExitNs: 1_000_050_000, Type: typ, Pid: 4242, Tgid: 4242, Ppid: 1, Uid: 1000, Mntns: 4026532001, Comm: "python3"}
}

func TestOpenDecoyResolvedThroughSymlink(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evOpen)
	k.Ret = 7
	k.Flags = 0                  // O_RDONLY
	k.Path = "/etc/app/settings" // symlink to the decoy
	ev, ok := d.Decode(k)
	if !ok {
		t.Fatal("not decoded")
	}
	f := ev.Facts
	if f.Kind != KindFileOpen || f.Outcome != OutcomeSuccess || f.Target.Access != "read" {
		t.Fatalf("%+v", f)
	}
	if f.Target.Path != "/opt/config/.db_recovery_creds" || !f.Target.PathResolved {
		t.Fatalf("symlink not resolved inside the root: %+v", f.Target)
	}
	if f.Workload.ID != "worker-01" || f.Workload.ContainerID != cidA || !f.Workload.Enrolled {
		t.Fatalf("%+v", f.Workload)
	}
	if time.Unix(0, int64(f.Received)).UTC() != time.Date(2026, 10, 19, 0, 0, 1, 50_000, time.UTC) {
		t.Fatalf("clock mapping: %d", f.Received)
	}
	if !strings.HasPrefix(f.ID, "ev-") || len(f.ID) != 27 {
		t.Fatal(f.ID)
	}
	if ev2, _ := d.Decode(k); ev2.Facts.ID != f.ID {
		t.Fatal("event id is not deterministic")
	}
}

func TestOpenRelativePathUsesCwd(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evOpen)
	k.Ret, k.Flags, k.Path = 3, 1, "../var/log/app/error.log" // O_WRONLY, relative to /workspace
	ev, _ := d.Decode(k)
	if ev.Facts.Target.Path != "/var/log/app/error.log" || !ev.Facts.Target.PathResolved || ev.Facts.Target.Access != "write" {
		t.Fatalf("%+v", ev.Facts.Target)
	}
}

func TestOpenFailedKeepsRawPathAndErrno(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evOpen)
	k.Ret, k.Flags, k.Path = -2, 2, "/etc/app/missing" // -ENOENT, O_RDWR
	ev, _ := d.Decode(k)
	f := ev.Facts
	if f.Outcome != OutcomeFailed || f.Errno != 2 || f.Target.PathResolved || f.Target.Path != "/etc/app/missing" || f.Target.Access != "rw" {
		t.Fatalf("%+v", f)
	}
}

func TestPathEscapingTheRootIsNotVouchedFor(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evOpen)
	k.Ret, k.Path = 5, "/etc/app/escape"
	ev, _ := d.Decode(k)
	if ev.Facts.Target.PathResolved || ev.Facts.Target.Path != "/etc/app/escape" {
		t.Fatalf("escape vouched for: %+v", ev.Facts.Target)
	}
}

func TestExecResolvesViaProcExeAndClassifies(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evExec)
	k.Ret, k.Path = 0, "python3" // relative name; /proc/pid/exe is authoritative
	k.Args = []string{"python3", "-c", "import os"}
	ev, _ := d.Decode(k)
	f := ev.Facts
	if f.Kind != KindProcessExec || f.Target.Exe != "/usr/bin/python3.12" || !f.Target.PathResolved {
		t.Fatalf("%+v", f.Target)
	}
	if f.Target.BinaryClass != "INTERPRETER" || f.Target.BinaryDetail != "INTERPRETER" {
		t.Fatalf("%+v", f.Target)
	}
	if len(ev.Payload.Argv) != 3 || ev.Payload.Argv[2] != "import os" {
		t.Fatal(ev.Payload)
	}
}

func TestExecFailedUsesRawPath(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evExec)
	k.Ret, k.Path = -13, "/usr/bin/curl" // EACCES; curl is not in the rootfs
	ev, _ := d.Decode(k)
	f := ev.Facts
	if f.Outcome != OutcomeFailed || f.Errno != 13 || f.Target.PathResolved || f.Target.BinaryClass != "NET_CLIENT" {
		t.Fatalf("%+v", f)
	}
}

func TestConnectV4V6AndPending(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evConnect)
	k.Ret, k.Family = -115, 2 // EINPROGRESS
	k.Port = 0x5000           // 80 in network byte order
	copy(k.Addr[:], []byte{203, 0, 113, 9})
	ev, _ := d.Decode(k)
	f := ev.Facts
	if f.Kind != KindNetConnect || f.Outcome != OutcomePending || f.Errno != 115 || f.Target.IP != "203.0.113.9" || f.Target.Port != 80 {
		t.Fatalf("%+v", f)
	}
	k6 := base(evConnect)
	k6.Ret, k6.Family, k6.Port = 0, 10, 0xBB01 // 443
	copy(k6.Addr[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	ev, _ = d.Decode(k6)
	if ev.Facts.Target.IP != "2001:db8::1" || ev.Facts.Target.Port != 443 || ev.Facts.Outcome != OutcomeSuccess {
		t.Fatalf("%+v", ev.Facts.Target)
	}
	// IPv4-mapped IPv6 is unmapped
	k6.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 20, 0, 5}
	ev, _ = d.Decode(k6)
	if ev.Facts.Target.IP != "10.20.0.5" {
		t.Fatal(ev.Facts.Target.IP)
	}
}

func TestUnwatchedNamespaceIsDropped(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evOpen)
	k.Mntns = 99
	if _, ok := d.Decode(k); ok {
		t.Fatal("unwatched namespace decoded")
	}
}

func TestEventJSONMatchesControllerContract(t *testing.T) {
	// The containment controller decodes events strictly; every key we emit must be
	// one it knows. This pins the wire shape.
	d, _ := testDecoder(t)
	k := base(evExec)
	k.Ret, k.Path, k.Args = 0, "/usr/bin/python3", []string{"python3"}
	ev, _ := d.Decode(k)
	want := []string{`"facts":{`, `"id":"ev-`, `"sensor":"ebpf"`, `"kind":"process_exec"`, `"outcome":"success"`,
		`"workload":{"id":"worker-01"`, `"container_id":"` + cidA + `"`, `"process":{"pid":4242`, `"target":{`,
		`"exe":"/usr/bin/python3.12"`, `"path_resolved":true`, `"binary_class":"INTERPRETER"`,
		`"t_kernel_enter_ns":1000000000`, `"t_received_ns":`, `"payload":{"argv":["python3"]}`}
	js := mustJSON(t, ev)
	for _, w := range want {
		if !strings.Contains(js, w) {
			t.Fatalf("missing %s in %s", w, js)
		}
	}
}
