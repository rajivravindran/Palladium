package main

// Binary identity: classify an executed program by WHAT IT IS, not what it is called.
//
// classifyBinary (event.go) keys on the file name, so `cp /usr/bin/curl /tmp/python3`
// turns a NET_CLIENT into an INTERPRETER. Here the sensor hashes the file that is
// actually running (/proc/<pid>/exe) and looks the hash up in a table of the enrolled
// workload's own image binaries (walked under /proc/<init pid>/root). The name the
// image gave that content is the canonical name; the class comes from it.
//
// Four outcomes, all visible in binary_detail so the controller and console can see
// how strong the evidence is:
//
//	hash known, name matches      → class from the name, detail as today
//	hash known, name differs      → class from the CANONICAL name, "RENAMED:<name>", renamed=true
//	hash unknown (not from image) → OTHER, "UNKNOWN_BINARY", foreign_binary=true
//	no table / hash unavailable   → name-based class, detail suffix ":NAME_ONLY"
//
// Everything here is bounded: 64 MiB per hashed file (above that ":UNHASHED", never a
// stall on the event path), 8192 entries and ~5 s of walking per workload table, a
// 4096-entry LRU for hashes keyed by (dev, ino, size, mtime).

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxHashBytes     = 64 << 20 // files above this are not hashed (never block the event path)
	hashCacheEntries = 4096
	imageWalkBudget  = 5 * time.Second // wall time per workload table build
	imageTableTTL    = 10 * time.Minute
)

// imageTableMax caps entries per workload table (a variable so tests can lower it).
var imageTableMax = 8192

// imageDirs are walked in this order; the first directory that holds a given
// content wins its name, so /usr/bin names a binary before a /bin alias does.
var imageDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}

// exeIdentity is what the sensor learned about the running file.
type exeIdentity struct {
	SHA256   string // hex; "" when not hashed (too big, or the file could not be read)
	Dev, Ino uint64
	Size     uint64
	TooBig   bool
}

// ---------------------------------------------------------------------------
// hash cache
// ---------------------------------------------------------------------------

type hashKey struct {
	dev, ino, size uint64
	mtimeNs        int64
}

// hashCache is a small LRU: the same inode is executed over and over inside a
// workload, and the image walk has usually hashed it already.
type hashCache struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[hashKey]*list.Element
}

type hashEntry struct {
	key hashKey
	sum string
}

func newHashCache(max int) *hashCache {
	if max <= 0 {
		max = hashCacheEntries
	}
	return &hashCache{max: max, ll: list.New(), m: map[hashKey]*list.Element{}}
}

func (c *hashCache) get(k hashKey) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		return "", false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*hashEntry).sum, true
}

func (c *hashCache) put(k hashKey, sum string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		el.Value.(*hashEntry).sum = sum
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(&hashEntry{key: k, sum: sum})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		delete(c.m, last.Value.(*hashEntry).key)
		c.ll.Remove(last)
	}
}

func (c *hashCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// hashFile identifies the regular file at p (symlinks, including the /proc/<pid>/exe
// magic link, are followed by open). A file above maxHashBytes is identified by
// dev/ino/size only and TooBig is set. cache may be nil.
func hashFile(p string, cache *hashCache) (exeIdentity, error) {
	f, err := os.Open(p)
	if err != nil {
		return exeIdentity{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return exeIdentity{}, err
	}
	if !fi.Mode().IsRegular() {
		return exeIdentity{}, errors.New("not a regular file")
	}
	id := exeIdentity{Size: uint64(fi.Size())}
	dev, ino, haveInode := fileInode(fi)
	id.Dev, id.Ino = dev, ino
	if fi.Size() > maxHashBytes {
		id.TooBig = true
		return id, nil
	}
	key := hashKey{dev: dev, ino: ino, size: id.Size, mtimeNs: fi.ModTime().UnixNano()}
	if cache != nil && haveInode {
		if sum, ok := cache.get(key); ok {
			id.SHA256 = sum
			return id, nil
		}
	}
	h := sha256.New()
	// LimitReader guards against a file that grows while we read it.
	if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes+1)); err != nil {
		return exeIdentity{}, err
	}
	id.SHA256 = hex.EncodeToString(h.Sum(nil))
	if cache != nil && haveInode {
		cache.put(key, id.SHA256)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// image table
// ---------------------------------------------------------------------------

// imageTable is what one workload's image says about its own binaries.
type imageTable struct {
	byHash  map[string]string // sha256 hex → canonical basename (first directory wins)
	alias   map[string]string // symlink basename → target basename, e.g. sh → dash
	partial bool              // entry cap or time budget hit, or a directory failed to read
	built   time.Time
}

// buildImageTable walks the standard binary directories under root (a container's
// /proc/<pid>/root, or a plain directory in tests). It never follows a symlink out
// of root: directories are resolved with resolveInRoot and files are opened through
// the resolved-in-root path, so a link to the host's /usr/bin cannot poison the table.
func buildImageTable(ctx context.Context, root string, cache *hashCache) *imageTable {
	t := &imageTable{byHash: map[string]string{}, alias: map[string]string{}, built: time.Now()}
	seenDir := map[string]bool{}
	for _, dir := range imageDirs {
		resolvedDir, err := resolveInRoot(root, dir)
		if err != nil || seenDir[resolvedDir] { // absent in this image, or /bin → /usr/bin already walked
			continue
		}
		seenDir[resolvedDir] = true
		entries, err := os.ReadDir(root + resolvedDir)
		if err != nil {
			t.partial = true
			continue
		}
		// Deterministic order so "first wins" means the same thing on every build.
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if ctx.Err() != nil || len(t.byHash) >= imageTableMax {
				t.partial = true
				return t
			}
			name := e.Name()
			switch {
			case e.Type()&os.ModeSymlink != 0:
				// Keep the image's own aliases (sh → dash, python3 → python3.12) so an
				// exec through the alias is not mistaken for a rename. Resolve the link
				// inside root to learn what it really names.
				target, err := resolveInRoot(root, path.Join(resolvedDir, name))
				if err != nil {
					continue
				}
				if base := path.Base(target); base != name {
					if _, dup := t.alias[name]; !dup {
						t.alias[name] = base
					}
				}
			case e.Type().IsRegular():
				id, err := hashFile(root+path.Join(resolvedDir, name), cache)
				if err != nil || id.SHA256 == "" {
					continue // unreadable or above the size cap: not identifiable by content
				}
				if _, dup := t.byHash[id.SHA256]; !dup {
					t.byHash[id.SHA256] = name
				}
			}
		}
	}
	return t
}

// Len reports how many distinct binaries the table knows.
func (t *imageTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.byHash)
}

// ---------------------------------------------------------------------------
// classification rule
// ---------------------------------------------------------------------------

// identityVerdict is the outcome of classifyByIdentity.
type identityVerdict struct {
	Class, Detail    string
	Renamed          bool
	ForeignBinary    bool
	HashInconclusive bool // class rests on the name only
}

// classifyByIdentity applies the four-outcome rule. table may be nil (no table for
// this workload); id.SHA256 may be "" (unreadable or too big). It is pure so the
// rule is testable without /proc.
func classifyByIdentity(table *imageTable, exe string, id exeIdentity) identityVerdict {
	nameClass, nameDetail := classifyBinary(exe)
	nameOnly := func(suffix string) identityVerdict {
		return identityVerdict{Class: nameClass, Detail: nameDetail + suffix, HashInconclusive: true}
	}
	if id.TooBig {
		return nameOnly(":UNHASHED")
	}
	if id.SHA256 == "" || table == nil {
		return nameOnly(":NAME_ONLY")
	}
	canonical, known := table.byHash[id.SHA256]
	if !known {
		if table.partial {
			// The walk did not finish, so "not in the table" is not "not in the image".
			return nameOnly(":NAME_ONLY")
		}
		return identityVerdict{Class: "OTHER", Detail: "UNKNOWN_BINARY", ForeignBinary: true}
	}
	base := filepath.Base(exe)
	if base == canonical {
		return identityVerdict{Class: nameClass, Detail: nameDetail}
	}
	if table.alias[base] == canonical {
		// Executed through a name the image itself declares for this content
		// (/bin/sh → dash). The class still comes from the content; the one exception
		// is a multi-call binary (busybox) that the content table cannot classify but
		// that genuinely behaves as the name it was invoked by.
		class, detail := classifyBinary(canonical)
		if class == "OTHER" {
			class, detail = nameClass, nameDetail
		}
		return identityVerdict{Class: class, Detail: detail}
	}
	// Known content under a name the image never gave it: a copied or renamed binary.
	// The class is what the content is, so a copied curl stays NET_CLIENT whatever it
	// is called now.
	class, _ := classifyBinary(canonical)
	return identityVerdict{Class: class, Detail: "RENAMED:" + canonical, Renamed: true}
}

// ---------------------------------------------------------------------------
// per-workload index, kept in step with enrollment
// ---------------------------------------------------------------------------

// imageIndex owns the hash cache and one imageTable per watched mount namespace.
// Enroller.Refresh calls refresh; Decoder calls classifyExec on the event path.
type imageIndex struct {
	ProcRoot string // where the host's /proc is mounted ("" → /proc)
	Log      func(format string, args ...any)
	// Build is the table builder; tests substitute a fake. nil → buildImageTable.
	Build func(ctx context.Context, root string, cache *hashCache) *imageTable

	cache    *hashCache
	mu       sync.RWMutex
	tables   map[uint32]*imageTable
	building bool
}

func newImageIndex(procRoot string, logf func(string, ...any)) *imageIndex {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &imageIndex{ProcRoot: procRoot, Log: logf, cache: newHashCache(hashCacheEntries), tables: map[uint32]*imageTable{}}
}

func (x *imageIndex) procRoot() string {
	if x.ProcRoot == "" {
		return "/proc"
	}
	return x.ProcRoot
}

func (x *imageIndex) table(mntns uint32) *imageTable {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.tables[mntns]
}

// setTable installs a table (tests, and the builder goroutine).
func (x *imageIndex) setTable(mntns uint32, t *imageTable) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.tables == nil {
		x.tables = map[uint32]*imageTable{}
	}
	x.tables[mntns] = t
}

// stale lists the namespaces whose table is missing or older than the TTL and
// drops tables for namespaces no longer enrolled. It is a pure bookkeeping step so
// the refresh decision is testable without walking anything.
func (x *imageIndex) stale(pids map[uint32]uint32, now time.Time) []uint32 {
	x.mu.Lock()
	defer x.mu.Unlock()
	for ns := range x.tables {
		if _, ok := pids[ns]; !ok {
			delete(x.tables, ns) // container restarted or was unenrolled: new namespace, new table
		}
	}
	var out []uint32
	for ns := range pids {
		t, ok := x.tables[ns]
		if !ok || now.Sub(t.built) >= imageTableTTL {
			out = append(out, ns)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// refresh is called on every enrollment refresh with mntns → init pid. Tables are
// (re)built in a single background goroutine so the enroller never waits on a
// hash walk, and only when the namespace is new or the table is older than the TTL:
// hashing all of /usr/bin on the 5 s refresh cadence would be absurd.
func (x *imageIndex) refresh(ctx context.Context, pids map[uint32]uint32) {
	todo := x.stale(pids, time.Now())
	if len(todo) == 0 {
		return
	}
	x.mu.Lock()
	if x.building {
		x.mu.Unlock()
		return
	}
	x.building = true
	x.mu.Unlock()
	go func() {
		defer func() {
			x.mu.Lock()
			x.building = false
			x.mu.Unlock()
		}()
		for _, ns := range todo {
			if ctx.Err() != nil {
				return
			}
			x.buildOne(ctx, ns, pids[ns])
		}
	}()
}

// buildOne builds the table for one namespace synchronously (bounded by imageWalkBudget).
func (x *imageIndex) buildOne(ctx context.Context, mntns, pid uint32) *imageTable {
	build := x.Build
	if build == nil {
		build = buildImageTable
	}
	wctx, cancel := context.WithTimeout(ctx, imageWalkBudget)
	defer cancel()
	root := procBaseIn(x.procRoot(), pid)
	t := build(wctx, root, x.cache)
	if t == nil {
		return nil
	}
	x.setTable(mntns, t)
	x.Log("image table: mntns %d pid %d: %d binaries, %d aliases, partial=%v", mntns, pid, len(t.byHash), len(t.alias), t.partial)
	return t
}

// classifyExec fills the identity facts for a successful exec by pid. exe is the
// resolved executable path (used for the name side of the rule). Failures never
// stop the event: they degrade to the name-based class with ":NAME_ONLY".
func (x *imageIndex) classifyExec(tgt *Target, mntns, pid uint32, exe string) {
	exeLink := procBaseIn(x.procRoot(), pid)
	exeLink = exeLink[:len(exeLink)-len("/root")] + "/exe"
	id, err := hashFile(exeLink, x.cache)
	if err != nil {
		id = exeIdentity{} // process gone already, or unreadable: the name is all we have
	}
	v := classifyByIdentity(x.table(mntns), exe, id)
	tgt.ExeSHA256 = id.SHA256
	tgt.ExeDev, tgt.ExeIno, tgt.ExeSize = id.Dev, id.Ino, id.Size
	tgt.BinaryClass, tgt.BinaryDetail = v.Class, v.Detail
	tgt.Renamed, tgt.ForeignBinary = v.Renamed, v.ForeignBinary
}

// classifyExecFile is classifyExec for an inline (LSM) exec, where the process has
// not switched images yet: the file is hashed through /proc/<pid>/root/<exe>, the
// path the kernel itself rendered for bprm->file. Same evidence caveat as every
// userspace read: the file could be replaced between the hook and the hash.
func (x *imageIndex) classifyExecFile(tgt *Target, mntns, pid uint32, exe string) {
	id, err := hashFile(procBaseIn(x.procRoot(), pid)+exe, x.cache)
	if err != nil {
		id = exeIdentity{}
	}
	v := classifyByIdentity(x.table(mntns), exe, id)
	tgt.ExeSHA256 = id.SHA256
	tgt.ExeDev, tgt.ExeIno, tgt.ExeSize = id.Dev, id.Ino, id.Size
	tgt.BinaryClass, tgt.BinaryDetail = v.Class, v.Detail
	tgt.Renamed, tgt.ForeignBinary = v.Renamed, v.ForeignBinary
}

// procBaseIn is procBase for an explicit /proc mount.
func procBaseIn(procRoot string, pid uint32) string {
	return strings.TrimSuffix(procRoot, "/") + "/" + strconv.FormatUint(uint64(pid), 10) + "/root"
}
