package main

// Turning what the kernel reported into an Event (Channel A facts + Channel B payload).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

const (
	evOpen    = 1
	evExec    = 2
	evConnect = 3
)

// kernelEvent is the platform-neutral copy of the BPF `struct event`. The
// linux/amd64 build fills it from the generated sensorEvent; tests build it directly.
type kernelEvent struct {
	EnterNs, ExitNs uint64
	Ret             int64
	Type            uint32
	Pid, Tgid, Ppid uint32
	Uid, Mntns      uint32
	Flags           uint32
	Family, Port    uint16
	Addr            [16]byte
	Comm            string
	Path            string
	Args            []string
	// LSM-only: the file's identity in the kernel's dev_t encoding, and the inline
	// marker. Zero / false for tracepoint events.
	Dev, Ino uint64
	Inline   bool
}

// Clock maps the kernel's monotonic nanoseconds to wall-clock time.
type Clock struct {
	wallAtBoot time.Time // wall time corresponding to monotonic 0
}

func (c Clock) Wall(monoNs uint64) time.Time {
	if c.wallAtBoot.IsZero() || monoNs == 0 {
		return time.Time{}
	}
	return c.wallAtBoot.Add(time.Duration(monoNs))
}

// Decoder turns kernelEvents into Events.
type Decoder struct {
	Sensor string
	Watch  *Watchlist
	Clock  Clock
	// ProcRoot is where the host's /proc is mounted (lets tests substitute a fixture tree).
	ProcRoot string
	// Now is called when the kernel clock cannot be mapped.
	Now func() time.Time
	// Images classifies executables by content (binident.go). nil keeps the
	// name-based classification only, as on sensors without the image index.
	Images *imageIndex
	// Inodes, when set, names a file by (mntns, dev, ino) for inline events whose
	// path bpf_d_path could not render (inodes.go). nil without -block-decoys.
	Inodes *inodeBlocker
	// Hosts, when set, names the destination of a connect from the sensor's own
	// resolution of the profiles' egress hostnames (hosts.go). nil without -resolve-hosts.
	Hosts hostLookup
}

func (d *Decoder) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

// eventID is deterministic for one kernel event so a retried delivery is a duplicate,
// not a new incident, and short enough for the API's identifier rule.
func eventID(sensor string, k kernelEvent) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%d|%d", sensor, k.Mntns, k.Pid, k.ExitNs, k.Type)))
	return "ev-" + hex.EncodeToString(sum[:12])
}

func outcomeOf(k kernelEvent) (Outcome, int64) {
	switch {
	case k.Inline && k.Ret < 0:
		// An LSM hook returned an error: the operation never happened because WE
		// said so. That is "blocked", never "failed" (which is the kernel's verdict).
		return OutcomeBlocked, -k.Ret
	case k.Ret >= 0:
		return OutcomeSuccess, 0
	case k.Type == evConnect && k.Ret == -int64(syscall.EINPROGRESS):
		return OutcomePending, int64(syscall.EINPROGRESS)
	default:
		return OutcomeFailed, -k.Ret
	}
}

// Decode builds the Event. ok is false when the mount namespace is not enrolled
// (the BPF filter should prevent that; a stale map entry during a refresh can't).
func (d *Decoder) Decode(k kernelEvent) (Event, bool) {
	ref, ok := d.Watch.Lookup(k.Mntns)
	if !ok {
		return Event{}, false
	}
	outcome, errno := outcomeOf(k)
	f := Facts{
		ID: eventID(d.Sensor, k), Sensor: d.Sensor, Outcome: outcome, Errno: errno, Workload: ref,
		Process:     ProcessRef{PID: k.Pid, TGID: k.Tgid, PPID: k.Ppid, UID: k.Uid, Comm: k.Comm},
		KernelEnter: k.EnterNs, KernelExit: k.ExitNs, Inline: k.Inline,
	}
	received := d.Clock.Wall(k.ExitNs)
	if received.IsZero() {
		received = d.now()
	}
	f.Received = uint64(received.UnixNano())
	ev := Event{Facts: f, mntns: k.Mntns}

	switch k.Type {
	case evOpen:
		f.Kind = KindFileOpen
		f.Target.Access = accessMode(k.Flags)
		if k.Inline {
			f.Target.Path, f.Target.PathResolved = d.inlinePath(k)
		} else {
			f.Target.Path, f.Target.PathResolved = d.resolvePath(k.Pid, k.Path)
		}
	case evExec:
		f.Kind = KindProcessExec
		if k.Inline {
			// bprm_check_security runs before the new image exists: /proc/<pid>/exe
			// is still the CALLER's binary, so the kernel-rendered path of bprm->file
			// is the truth here and the content hash is taken from that file.
			exe, resolved := d.inlinePath(k)
			f.Target.Exe = exe
			f.Target.PathResolved = resolved
			f.Target.BinaryClass, f.Target.BinaryDetail = classifyBinary(exe)
			if d.Images != nil && outcome == OutcomeSuccess && resolved {
				d.Images.classifyExecFile(&f.Target, k.Mntns, k.Pid, exe)
			}
			break
		}
		exe, resolved := d.resolvePath(k.Pid, k.Path)
		if outcome == OutcomeSuccess {
			// The new image is running: /proc/<pid>/exe says exactly which file, so
			// the lexical candidate is confirmed by inode, or replaced by the truth.
			if p, ok := d.resolveExe(k.Pid, exe); ok {
				exe, resolved = p, true
			} else {
				resolved = false
			}
		}
		f.Target.Exe = exe
		f.Target.PathResolved = resolved
		f.Target.BinaryClass, f.Target.BinaryDetail = classifyBinary(exe)
		if d.Images != nil && outcome == OutcomeSuccess {
			// Replace the name-based guess with what the file's content says. A failed
			// exec started no new image, so /proc/<pid>/exe would be the caller's.
			d.Images.classifyExec(&f.Target, k.Mntns, k.Pid, exe)
		}
		ev.Payload.Argv = k.Args
	case evConnect:
		f.Kind = KindNetConnect
		var addr netip.Addr
		switch k.Family {
		case 2:
			addr = netip.AddrFrom4([4]byte{k.Addr[0], k.Addr[1], k.Addr[2], k.Addr[3]})
		case 10:
			addr = netip.AddrFrom16(k.Addr).Unmap()
		}
		if addr.IsValid() {
			f.Target.IP = addr.String()
			if d.Hosts != nil {
				f.Target.Host, _ = d.Hosts.Lookup(f.Target.IP)
			}
		}
		f.Target.Port = (k.Port >> 8) | (k.Port << 8) // network byte order → host
	default:
		return Event{}, false
	}
	ev.Facts = f
	return ev, true
}

// inlinePath names the file of an LSM event. The kernel rendered the path itself
// (bpf_d_path, relative to the caller's root, symlinks already followed), so it
// is resolved by construction. When d_path failed (a path over 255 bytes, in
// practice) the (dev, ino) pair is looked up in the blocked-inode table, which is
// the one place userspace knows a name for an inode; anything else stays unnamed
// rather than guessed.
func (d *Decoder) inlinePath(k kernelEvent) (string, bool) {
	if k.Path != "" {
		return k.Path, true
	}
	if d.Inodes != nil {
		if p, ok := d.Inodes.lookup(k.Mntns, k.Dev, k.Ino); ok {
			return p, true
		}
	}
	return "", false
}

// resolvePath turns the path string a process handed to the kernel into the
// canonical absolute path inside that process's own root, walking it component by
// component under /proc/<pid>/root (and /proc/<pid>/cwd for relative paths). Symlinks
// are followed with absolute targets re-rooted at the process root, which is how the
// kernel itself resolves them for that process — filepath.EvalSymlinks would resolve
// them against the host root and lie. resolved=false means we could not do this
// (process already gone, file gone, too many links) and the raw string is returned
// for display only.
//
// This is a userspace read after the syscall and therefore racy: the file can be
// renamed between the open and our look. It is evidence, not a lock. The
// containment controller treats PathResolved as "sensor computed the canonical
// path", and the policy README already says lexical matching is not filesystem
// authorization.
func (d *Decoder) resolvePath(pid uint32, raw string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	base := d.procBase(pid)
	p := raw
	if !strings.HasPrefix(p, "/") {
		cwd, err := os.Readlink(d.procBase(pid)[:len(base)-len("/root")] + "/cwd")
		if err != nil || !strings.HasPrefix(cwd, "/") {
			return raw, false
		}
		p = path.Join(cwd, raw)
	}
	resolved, err := resolveInRoot(base, p)
	if err != nil {
		return raw, false
	}
	return resolved, true
}

func (d *Decoder) procBase(pid uint32) string {
	procRoot := d.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	return fmt.Sprintf("%s/%d/root", procRoot, pid)
}

// resolveInRoot canonicalises p as seen by a process whose root is base.
func resolveInRoot(base, p string) (string, error) {
	const maxLinks = 40
	links := 0
	resolved := "/"
	rest := strings.Split(path.Clean(p), "/")
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, c)
		fi, err := os.Lstat(base + next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		links++
		if links > maxLinks {
			return "", errors.New("too many symlinks")
		}
		target, err := os.Readlink(base + next)
		if err != nil {
			return "", err
		}
		// Splice the link target in front of what is left to walk. Absolute targets
		// restart from the process root; relative ones continue from the link's directory.
		if strings.HasPrefix(target, "/") {
			resolved = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	if _, err := os.Lstat(base + resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// resolveExe confirms which file a successful exec is running from /proc/<pid>/exe.
// The path string the kernel reports for exe is in the reader's view, so it is used
// only as a candidate; the match is on device+inode against the file inside the
// process root.
func (d *Decoder) resolveExe(pid uint32, candidate string) (string, bool) {
	base := d.procBase(pid)
	exeLink := base[:len(base)-len("/root")] + "/exe"
	exeInfo, err := os.Stat(exeLink)
	if err != nil {
		return "", false
	}
	try := func(p string) bool {
		fi, err := os.Stat(base + p)
		return err == nil && os.SameFile(fi, exeInfo)
	}
	if candidate != "" && try(candidate) {
		return candidate, true
	}
	if target, err := os.Readlink(exeLink); err == nil {
		target = strings.TrimSuffix(target, " (deleted)")
		// From the host, the link usually carries the rootfs mount prefix
		// (…/overlay/<id>/merged/usr/bin/x). Try every suffix inside the process root;
		// the inode comparison makes a wrong guess impossible.
		parts := strings.Split(strings.TrimPrefix(target, "/"), "/")
		for i := range parts {
			cand := "/" + strings.Join(parts[i:], "/")
			if r, err := resolveInRoot(base, cand); err == nil && try(r) {
				return r, true
			}
		}
	}
	return "", false
}

// cstr converts a NUL-terminated fixed buffer.
func cstr(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
