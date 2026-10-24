package main

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	policy "river3.local/policy"
)

func TestKernelDevEncoding(t *testing.T) {
	// stat(2) st_dev → kernel MKDEV(major, minor): the two encodings differ above
	// the first byte of the minor, which is exactly where overlayfs anonymous
	// devices (0:3xx) live.
	cases := []struct {
		major, minor uint64
	}{{8, 1}, {0, 300}, {0, 35}, {259, 4}, {253, 0x1234}}
	for _, c := range cases {
		st := (c.minor & 0xff) | (c.major << 8) | ((c.minor &^ 0xff) << 12) // new_encode_dev
		if got, want := kernelDev(st), c.major<<20|c.minor; got != want {
			t.Errorf("major %d minor %d: st_dev %#x → %#x, want %#x", c.major, c.minor, st, got, want)
		}
	}
}

// The kernel prints each mount's superblock device as major:minor in mountinfo;
// stat on the mount point gives st_dev. The two must agree through kernelDev, or
// the BPF map key would never match inode->i_sb->s_dev.
func TestKernelDevMatchesMountinfo(t *testing.T) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Skip("no /proc/self/mountinfo")
	}
	defer f.Close()
	checked := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mm := strings.SplitN(fields[2], ":", 2)
		var st syscall.Stat_t
		if syscall.Stat(fields[4], &st) != nil {
			continue
		}
		major, _ := strconv.ParseUint(mm[0], 10, 64)
		minor, _ := strconv.ParseUint(mm[1], 10, 64)
		// A mount point shadowed by another mount reports the top mount; skip mismatches
		// of that kind by only asserting when the mountinfo pair itself agrees.
		if kernelDev(uint64(st.Dev)) != major<<20|minor {
			if dup := strings.Count(mountedAt(t, fields[4]), "\n"); dup > 1 {
				continue
			}
			t.Errorf("%s: mountinfo %s:%s, stat dev %#x → %#x", fields[4], mm[0], mm[1], st.Dev, kernelDev(uint64(st.Dev)))
		}
		checked++
	}
	if checked == 0 {
		t.Skip("nothing to check")
	}
}

func mountedAt(t *testing.T, mp string) string {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 4 && f[4] == mp {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// blockerRoot builds a container-like rootfs and a fake /proc for it.
func blockerRoot(t *testing.T) (procRoot string, rootfs string) {
	t.Helper()
	tmp := t.TempDir()
	rootfs = filepath.Join(tmp, "rootfs")
	for _, d := range []string{"opt/config", "root/.aws/sub", "etc/app", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(rootfs, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(rootfs, "opt/config/.db_recovery_creds"), []byte("inert"), 0o600)
	_ = os.WriteFile(filepath.Join(rootfs, "root/.aws/credentials"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(rootfs, "root/.aws/sub/token"), []byte("y"), 0o600)
	_ = os.WriteFile(filepath.Join(rootfs, "etc/app/a.conf"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(rootfs, "etc/app/b.conf"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(rootfs, "etc/app/notes.txt"), nil, 0o644)
	_ = os.Symlink("/opt/config/.db_recovery_creds", filepath.Join(rootfs, "etc/app/link"))
	_ = os.Symlink(filepath.Join(tmp, "outside"), filepath.Join(rootfs, "etc/app/escape"))
	_ = os.WriteFile(filepath.Join(tmp, "outside"), nil, 0o644)
	procRoot = filepath.Join(tmp, "proc")
	_ = os.MkdirAll(filepath.Join(procRoot, "100"), 0o755)
	_ = os.Symlink(rootfs, filepath.Join(procRoot, "100", "root"))
	return procRoot, rootfs
}

func TestResolvePatterns(t *testing.T) {
	_, rootfs := blockerRoot(t)
	got := resolvePatterns(context.Background(), rootfs, []string{
		"/opt/config/.db_recovery_creds",
		"/root/.aws/**",
		"/etc/shadow",     // absent: skipped, not an error
		"/etc/app/*.conf", // star within a segment
		"/etc/app/link",   // symlink inside the root resolves to the decoy (deduplicated)
		"/etc/app/escape", // symlink out of the root: not vouched for
		"/opt/config/**",  // subtree that is already partly listed
		"/nonexistent/**", // nothing
	})
	sort.Strings(got)
	want := []string{"/etc/app/a.conf", "/etc/app/b.conf", "/opt/config", "/opt/config/.db_recovery_creds",
		"/root/.aws", "/root/.aws/credentials", "/root/.aws/sub", "/root/.aws/sub/token"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestResolvePatternsIsBounded(t *testing.T) {
	_, rootfs := blockerRoot(t)
	old := inodeExpandMax
	defer func() { inodeExpandMax = old }()
	inodeExpandMax = 2
	got := resolvePatterns(context.Background(), rootfs, []string{"/root/.aws/**", "/etc/app/*.conf"})
	if len(got) != 2 {
		t.Fatalf("cap not applied: %v", got)
	}
}

func TestInodeBlockerRefresh(t *testing.T) {
	procRoot, rootfs := blockerRoot(t)
	profiles := map[string]*policy.Profile{
		"diagnostic-worker": {Name: "diagnostic-worker", Decoys: []string{"/opt/config/.db_recovery_creds"}, ProtectRead: []string{"/root/.aws/**", "/etc/shadow"}},
	}
	var applied map[inodeKey]bool
	var logs []string
	b := newInodeBlocker(profiles, func(d map[inodeKey]bool) error { applied = d; return nil }, func(f string, a ...any) { logs = append(logs, f) })
	b.procRoot = procRoot
	procs := map[uint32]watchedProc{
		4026532001: {PID: 100, Profile: "diagnostic-worker", Asset: "worker-01"},
		4026532002: {PID: 100, Profile: "no-such-profile", Asset: "worker-02"},
		4026532003: {PID: 0, Profile: "diagnostic-worker", Asset: "bare-mntns"},
	}
	if err := b.refresh(context.Background(), procs); err != nil {
		t.Fatal(err)
	}
	// decoy + /root/.aws + credentials + sub + sub/token = 5 inodes, all in namespace ...001
	if len(applied) != 5 || b.size() != 5 {
		t.Fatalf("applied %d: %v", len(applied), applied)
	}
	for k := range applied {
		if k.Mntns != 4026532001 {
			t.Fatalf("inode leaked into another namespace: %+v", k)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(rootfs, "opt/config/.db_recovery_creds"), &st); err != nil {
		t.Fatal(err)
	}
	key := inodeKey{Dev: kernelDev(uint64(st.Dev)), Ino: st.Ino, Mntns: 4026532001}
	if !applied[key] {
		t.Fatalf("decoy inode %+v not in the set %v", key, applied)
	}
	if p, ok := b.lookup(4026532001, key.Dev, key.Ino); !ok || p != "/opt/config/.db_recovery_creds" {
		t.Fatalf("lookup %q %v", p, ok)
	}
	if _, ok := b.lookup(4026532002, key.Dev, key.Ino); ok {
		t.Fatal("same inode must not be named for a namespace that does not block it")
	}
	if len(logs) != 2 { // unknown profile + the count line
		t.Fatalf("logs %v", logs)
	}
	// Second refresh: the unknown-profile warning is not repeated, the count line
	// only appears on change; a decoy created later is picked up.
	logs = nil
	_ = os.WriteFile(filepath.Join(rootfs, "etc/shadow"), []byte("root:*"), 0o600)
	if err := b.refresh(context.Background(), procs); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 6 || len(logs) != 1 {
		t.Fatalf("applied %d logs %v", len(applied), logs)
	}
	// A workload that disappears takes its inodes with it.
	delete(procs, 4026532001)
	_ = b.refresh(context.Background(), procs)
	if len(applied) != 0 || b.size() != 0 {
		t.Fatalf("stale inodes kept: %v", applied)
	}
}
