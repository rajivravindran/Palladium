package main

// Inline blocking (-block-decoys): which files the LSM hook must refuse to open.
//
// For every enrolled workload the sensor takes its profile's `decoys` and
// `protected_read` patterns, resolves them inside the container's own root
// (/proc/<init pid>/root, the same walk the decoder uses for paths) and records the
// (dev, ino) of each file. The kernel program denies file_open on a listed inode
// with -EPERM and reports the event with outcome "blocked".
//
// Why inodes and not paths: the kernel hook sees a `struct file`, whose identity
// is its inode. A hard link, a bind mount or a rename cannot dodge an inode match
// the way they dodge a string match, and the lookup is one hash probe. The cost
// is that the set must be re-resolved when files appear or change, which is why
// it is rebuilt on every enrollment refresh (5 s by default) and why a decoy
// created after enrollment is covered at the next refresh, not instantly.
//
// Why the mount namespace is in the key: two containers from the same image share
// lower-layer inodes. Without mntns, enrolling a decoy for one would block the
// same file in every other container on the host.

import (
	"context"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	policy "river3.local/policy"
)

// inodeKey identifies one blocked file for one workload. Dev is in the kernel's
// dev_t encoding (see kernelDev), matching what the LSM program reads from
// inode->i_sb->s_dev.
type inodeKey struct {
	Dev, Ino uint64
	Mntns    uint32
}

// Bounds for expanding `**` patterns: a protected subtree like /root/.aws/** is
// expected to hold a handful of files; a pattern pointed at /usr would otherwise
// turn each refresh into a filesystem walk. inodeExpandMax is a variable so tests
// can lower it.
var inodeExpandMax = 4096

const inodeExpandBudget = 2 * time.Second

// kernelDev converts a stat(2) st_dev into the kernel's internal dev_t: 12 bits
// of major above 20 bits of minor (MKDEV). Userspace sees `new_encode_dev`:
// minor's low byte, then major in bits 8..19, then the rest of the minor at bit 12.
func kernelDev(st uint64) uint64 {
	major := (st >> 8) & 0xfff
	minor := (st & 0xff) | ((st >> 12) & 0xfff00)
	return major<<20 | minor
}

// watchedProc is what the enroller knows about one watched namespace.
type watchedProc struct {
	PID     uint32
	Profile string
	Asset   string
}

// inodeBlocker resolves profile paths to inodes and mirrors the kernel map.
type inodeBlocker struct {
	profiles map[string]*policy.Profile
	procRoot string // where the host's /proc is mounted ("" → /proc)
	// apply writes the desired set to the BPF map; nil in tests.
	apply func(desired map[inodeKey]bool) error
	log   func(format string, args ...any)

	mu     sync.RWMutex
	paths  map[inodeKey]string // what each blocked inode is called inside its workload
	warned map[string]bool     // asset ids whose profile is unknown (logged once)
}

func newInodeBlocker(profiles map[string]*policy.Profile, apply func(map[inodeKey]bool) error, logf func(string, ...any)) *inodeBlocker {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &inodeBlocker{profiles: profiles, apply: apply, log: logf, paths: map[inodeKey]string{}, warned: map[string]bool{}}
}

// lookup names a blocked inode (for events whose path the kernel could not render).
func (b *inodeBlocker) lookup(mntns uint32, dev, ino uint64) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	p, ok := b.paths[inodeKey{Dev: dev, Ino: ino, Mntns: mntns}]
	return p, ok
}

// size reports how many inodes are currently blocked (tests, logs).
func (b *inodeBlocker) size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.paths)
}

// refresh rebuilds the set for the given namespaces and pushes it to the kernel.
// It runs synchronously inside Enroller.Refresh: enforcement must be in place
// when the workload is declared watched, not a goroutine later.
func (b *inodeBlocker) refresh(ctx context.Context, procs map[uint32]watchedProc) error {
	desired := map[inodeKey]string{}
	// Deterministic order so logs and the first-wins rule are stable run to run.
	nss := make([]uint32, 0, len(procs))
	for ns := range procs {
		nss = append(nss, ns)
	}
	sort.Slice(nss, func(i, j int) bool { return nss[i] < nss[j] })
	for _, ns := range nss {
		wp := procs[ns]
		if wp.PID == 0 {
			continue // a bare mntns enrollment has no root to resolve in
		}
		prof, ok := b.profiles[wp.Profile]
		if !ok {
			if !b.warned[wp.Asset] {
				b.warned[wp.Asset] = true
				b.log("block-decoys: %s: profile %q not in the profile directory; nothing blocked for it", wp.Asset, wp.Profile)
			}
			continue
		}
		delete(b.warned, wp.Asset)
		root := procBaseIn(b.procRootDir(), wp.PID)
		patterns := append(append([]string{}, prof.Decoys...), prof.ProtectRead...)
		for _, p := range resolvePatterns(ctx, root, patterns) {
			fi, err := os.Lstat(root + p)
			if err != nil {
				continue
			}
			dev, ino, ok := fileInode(fi)
			if !ok {
				continue
			}
			key := inodeKey{Dev: kernelDev(dev), Ino: ino, Mntns: ns}
			if _, dup := desired[key]; !dup {
				desired[key] = p
			}
		}
	}
	if b.apply != nil {
		set := make(map[inodeKey]bool, len(desired))
		for k := range desired {
			set[k] = true
		}
		if err := b.apply(set); err != nil {
			return err
		}
	}
	b.mu.Lock()
	changed := len(desired) != len(b.paths)
	if !changed {
		for k := range desired {
			if _, ok := b.paths[k]; !ok {
				changed = true
				break
			}
		}
	}
	b.paths = desired
	b.mu.Unlock()
	if changed {
		b.log("block-decoys: %d inode(s) blocked across %d namespace(s)", len(desired), len(procs))
	}
	return nil
}

func (b *inodeBlocker) procRootDir() string {
	if b.procRoot == "" {
		return "/proc"
	}
	return b.procRoot
}

// resolvePatterns expands profile path patterns inside root to concrete,
// canonical paths that exist right now. Supported, matching policy's globMatch:
// a literal path, `*` within one segment, and a trailing `/**` for a subtree
// (which includes the directory itself, so listing it is denied too). Missing
// files are simply absent from the result; the next refresh looks again.
func resolvePatterns(ctx context.Context, root string, patterns []string) []string {
	deadline := time.Now().Add(inodeExpandBudget)
	seen := map[string]bool{}
	var out []string
	add := func(p string) bool {
		if len(out) >= inodeExpandMax || ctx.Err() != nil || time.Now().After(deadline) {
			return false
		}
		r, err := resolveInRoot(root, p)
		if err != nil || seen[r] {
			return true
		}
		seen[r] = true
		out = append(out, r)
		return true
	}
	for _, pat := range patterns {
		subtree := strings.HasSuffix(pat, "/**")
		base := strings.TrimSuffix(pat, "/**")
		for _, dir := range expandStars(root, base) {
			if !add(dir) {
				return out
			}
			if subtree {
				walkInRoot(root, dir, func(p string) bool { return add(p) })
			}
		}
	}
	return out
}

// expandStars expands `*` wildcards segment by segment under root, without
// following symlinks out of the root (resolveInRoot does the final check).
func expandStars(root, pattern string) []string {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}
	}
	segs := strings.Split(strings.Trim(path.Clean(pattern), "/"), "/")
	cur := []string{"/"}
	for _, seg := range segs {
		var next []string
		for _, dir := range cur {
			if !strings.Contains(seg, "*") {
				next = append(next, path.Join(dir, seg))
				continue
			}
			resolved, err := resolveInRoot(root, dir)
			if err != nil {
				continue
			}
			entries, err := os.ReadDir(root + resolved)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ok, _ := path.Match(seg, e.Name()); ok {
					next = append(next, path.Join(dir, e.Name()))
				}
			}
		}
		cur = next
		if len(cur) == 0 {
			break
		}
	}
	return cur
}

// walkInRoot visits every entry under dir (a resolved in-root path), depth first,
// never following symlinked directories. visit returns false to stop.
func walkInRoot(root, dir string, visit func(p string) bool) bool {
	entries, err := os.ReadDir(root + dir)
	if err != nil {
		return true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		if !visit(p) {
			return false
		}
		if e.IsDir() { // IsDir is false for a symlink to a directory
			if !walkInRoot(root, p, visit) {
				return false
			}
		}
	}
	return true
}
