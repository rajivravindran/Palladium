package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeTable is an image whose curl, dash and busybox contents are known.
func fakeTable() *imageTable {
	return &imageTable{
		byHash: map[string]string{sumOf([]byte("curl")): "curl", sumOf([]byte("dash")): "dash",
			sumOf([]byte("busybox")): "busybox", sumOf([]byte("py")): "python3.12"},
		alias: map[string]string{"sh": "dash", "ls": "busybox", "python3": "python3.12"},
		built: time.Now(),
	}
}

func TestClassifyByIdentityRule(t *testing.T) {
	tbl := fakeTable()
	partial := fakeTable()
	partial.partial = true
	cases := []struct {
		name  string
		table *imageTable
		exe   string
		id    exeIdentity
		class string
		det   string
		ren   bool
		frn   bool
	}{
		// a) hash known, name matches
		{"curl is curl", tbl, "/usr/bin/curl", exeIdentity{SHA256: sumOf([]byte("curl"))}, "NET_CLIENT", "NET_CLIENT", false, false},
		// b) hash known, name differs: class from content, flagged
		{"curl copied to python3", tbl, "/tmp/python3", exeIdentity{SHA256: sumOf([]byte("curl"))}, "NET_CLIENT", "RENAMED:curl", true, false},
		{"dash copied to cat", tbl, "/tmp/cat", exeIdentity{SHA256: sumOf([]byte("dash"))}, "INTERPRETER", "RENAMED:dash", true, false},
		// image aliases are not renames
		{"sh alias of dash", tbl, "/bin/sh", exeIdentity{SHA256: sumOf([]byte("dash"))}, "INTERPRETER", "SHELL", false, false},
		{"python3 alias", tbl, "/usr/bin/python3", exeIdentity{SHA256: sumOf([]byte("py"))}, "INTERPRETER", "INTERPRETER", false, false},
		{"busybox as ls", tbl, "/bin/ls", exeIdentity{SHA256: sumOf([]byte("busybox"))}, "DIAGNOSTIC", "FILE_UTIL", false, false},
		// c) hash unknown: not from the image
		{"downloaded binary", tbl, "/tmp/python3", exeIdentity{SHA256: sumOf([]byte("evil"))}, "OTHER", "UNKNOWN_BINARY", false, true},
		// d) weaker evidence falls back to the name, visibly
		{"no table", nil, "/tmp/python3", exeIdentity{SHA256: sumOf([]byte("curl"))}, "INTERPRETER", "INTERPRETER:NAME_ONLY", false, false},
		{"partial table miss", partial, "/usr/bin/wget", exeIdentity{SHA256: sumOf([]byte("new"))}, "NET_CLIENT", "NET_CLIENT:NAME_ONLY", false, false},
		{"unreadable", tbl, "/usr/bin/curl", exeIdentity{}, "NET_CLIENT", "NET_CLIENT:NAME_ONLY", false, false},
		{"too big", tbl, "/opt/app/server", exeIdentity{TooBig: true, Size: 1 << 30}, "OTHER", "OTHER:UNHASHED", false, false},
	}
	allowed := map[string]bool{}
	for _, c := range EngineClasses {
		allowed[c] = true
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := classifyByIdentity(c.table, c.exe, c.id)
			if v.Class != c.class || v.Detail != c.det || v.Renamed != c.ren || v.ForeignBinary != c.frn {
				t.Fatalf("got %+v", v)
			}
			if !allowed[v.Class] {
				t.Fatalf("%q is not an engine class", v.Class)
			}
		})
	}
}

func TestHashFileAndCache(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("curl"), 0o755); err != nil {
		t.Fatal(err)
	}
	cache := newHashCache(2)
	id, err := hashFile(p, cache)
	if err != nil {
		t.Fatal(err)
	}
	if id.SHA256 != sumOf([]byte("curl")) || id.Size != 4 || id.TooBig {
		t.Fatalf("%+v", id)
	}
	if id.Dev == 0 && id.Ino == 0 {
		t.Fatal("no inode identity on a unix host")
	}
	if cache.len() != 1 {
		t.Fatalf("cache has %d entries", cache.len())
	}
	// Second hash is served from the cache: same key, same answer, no new entry.
	if _, err := hashFile(p, cache); err != nil || cache.len() != 1 {
		t.Fatalf("cache miss on identical file: err=%v len=%d", err, cache.len())
	}
	// A symlink is followed (that is how /proc/<pid>/exe is read).
	link := filepath.Join(dir, "link")
	_ = os.Symlink(p, link)
	if id2, err := hashFile(link, cache); err != nil || id2.SHA256 != id.SHA256 || cache.len() != 1 {
		t.Fatalf("symlink: %+v %v len=%d", id2, err, cache.len())
	}
	// LRU eviction at the cap.
	for i, body := range []string{"two", "three"} {
		q := filepath.Join(dir, "f"+string(rune('0'+i)))
		_ = os.WriteFile(q, []byte(body), 0o755)
		if _, err := hashFile(q, cache); err != nil {
			t.Fatal(err)
		}
	}
	if cache.len() != 2 {
		t.Fatalf("LRU not bounded: %d", cache.len())
	}
	// Directory and missing file are errors, not panics.
	if _, err := hashFile(dir, cache); err == nil {
		t.Fatal("directory hashed")
	}
	if _, err := hashFile(filepath.Join(dir, "nope"), cache); err == nil {
		t.Fatal("missing file hashed")
	}
}

func TestHashCacheLRUOrder(t *testing.T) {
	c := newHashCache(2)
	k := func(i uint64) hashKey { return hashKey{ino: i} }
	c.put(k(1), "a")
	c.put(k(2), "b")
	c.get(k(1)) // 1 is now most recent
	c.put(k(3), "c")
	if _, ok := c.get(k(2)); ok {
		t.Fatal("least recently used entry survived")
	}
	if v, ok := c.get(k(1)); !ok || v != "a" {
		t.Fatal("recently used entry evicted")
	}
}

// fakeRootfs lays out a small image: /usr/bin/{curl,dash,python3.12}, /bin -> usr/bin
// (merged usr), /bin/sh -> dash, /usr/bin/python3 -> python3.12, /usr/local/bin/tool,
// a symlink escaping the root, and a non-regular entry.
func fakeRootfs(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	root := filepath.Join(tmp, "rootfs")
	for _, d := range []string{"usr/bin", "usr/local/bin", "usr/sbin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(root, "usr/bin/curl"), []byte("curl"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/dash"), []byte("dash"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/python3.12"), []byte("py"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/local/bin/tool"), []byte("tool"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/sbin/curl-copy"), []byte("curl"), 0o755) // same content, later dir
	_ = os.Symlink("usr/bin", filepath.Join(root, "bin"))
	_ = os.Symlink("dash", filepath.Join(root, "usr/bin/sh"))
	_ = os.Symlink("python3.12", filepath.Join(root, "usr/bin/python3"))
	_ = os.WriteFile(filepath.Join(tmp, "host-binary"), []byte("host"), 0o755)
	_ = os.Symlink(filepath.Join(tmp, "host-binary"), filepath.Join(root, "usr/bin/escape"))
	_ = os.Mkdir(filepath.Join(root, "usr/bin/adir"), 0o755)
	return root
}

func TestBuildImageTable(t *testing.T) {
	root := fakeRootfs(t)
	tbl := buildImageTable(context.Background(), root, newHashCache(16))
	if tbl.partial {
		t.Fatal("complete walk marked partial")
	}
	want := map[string]string{sumOf([]byte("curl")): "curl", sumOf([]byte("dash")): "dash",
		sumOf([]byte("py")): "python3.12", sumOf([]byte("tool")): "tool"}
	if len(tbl.byHash) != len(want) {
		t.Fatalf("table %v", tbl.byHash)
	}
	for h, name := range want {
		if tbl.byHash[h] != name {
			t.Fatalf("%s -> %q, want %q", h[:8], tbl.byHash[h], name)
		}
	}
	// /usr/bin was walked first, so curl-copy in /usr/sbin did not take the name.
	if tbl.byHash[sumOf([]byte("curl"))] != "curl" {
		t.Fatal("first-wins order broken")
	}
	if tbl.alias["sh"] != "dash" || tbl.alias["python3"] != "python3.12" {
		t.Fatalf("aliases %v", tbl.alias)
	}
	if _, ok := tbl.byHash[sumOf([]byte("host"))]; ok {
		t.Fatal("a symlink out of the root was followed")
	}
	if _, ok := tbl.alias["escape"]; ok {
		t.Fatal("escaping symlink recorded as an alias")
	}
	// The whole thing composes: an exec of /tmp/python3 whose content is curl.
	v := classifyByIdentity(tbl, "/tmp/python3", exeIdentity{SHA256: sumOf([]byte("curl"))})
	if v.Class != "NET_CLIENT" || v.Detail != "RENAMED:curl" || !v.Renamed {
		t.Fatalf("%+v", v)
	}
	v = classifyByIdentity(tbl, "/bin/sh", exeIdentity{SHA256: sumOf([]byte("dash"))})
	if v.Class != "INTERPRETER" || v.Renamed {
		t.Fatalf("%+v", v)
	}
}

func TestBuildImageTableRespectsCapAndDeadline(t *testing.T) {
	root := fakeRootfs(t)
	old := imageTableMax
	imageTableMax = 2
	defer func() { imageTableMax = old }()
	tbl := buildImageTable(context.Background(), root, nil)
	if len(tbl.byHash) != 2 || !tbl.partial {
		t.Fatalf("cap not respected: %d entries partial=%v", len(tbl.byHash), tbl.partial)
	}
	imageTableMax = old
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tbl = buildImageTable(ctx, root, nil)
	if !tbl.partial || len(tbl.byHash) != 0 {
		t.Fatalf("expired deadline not honoured: %d entries partial=%v", len(tbl.byHash), tbl.partial)
	}
	// A root with none of the directories yields an empty, complete table (nothing
	// to classify, every exec is then a foreign binary — by design).
	tbl = buildImageTable(context.Background(), t.TempDir(), nil)
	if tbl.partial || len(tbl.byHash) != 0 {
		t.Fatalf("%+v", tbl)
	}
}

func TestImageIndexStaleBookkeeping(t *testing.T) {
	x := newImageIndex("", nil)
	now := time.Now()
	fresh := &imageTable{byHash: map[string]string{}, built: now}
	old := &imageTable{byHash: map[string]string{}, built: now.Add(-imageTableTTL - time.Second)}
	x.setTable(1, fresh)
	x.setTable(2, old)
	x.setTable(3, fresh) // 3 is no longer enrolled
	got := x.stale(map[uint32]uint32{1: 10, 2: 20, 4: 40}, now)
	if fmt.Sprint(got) != "[2 4]" { // 2 is past the TTL, 4 has no table, 1 is fresh
		t.Fatalf("stale = %v", got)
	}
	if x.table(3) != nil {
		t.Fatal("table for an unenrolled namespace kept")
	}
	if x.table(1) != fresh {
		t.Fatal("fresh table dropped")
	}
}

func TestImageIndexRefreshBuildsInBackground(t *testing.T) {
	x := newImageIndex(t.TempDir(), nil)
	built := make(chan string, 4)
	x.Build = func(_ context.Context, root string, _ *hashCache) *imageTable {
		built <- root
		return &imageTable{byHash: map[string]string{"h": "curl"}, built: time.Now()}
	}
	x.refresh(context.Background(), map[uint32]uint32{7: 4242})
	select {
	case root := <-built:
		if !strings.HasSuffix(root, "/4242/root") {
			t.Fatal(root)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("builder never ran")
	}
	deadline := time.Now().Add(5 * time.Second)
	for x.table(7) == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if x.table(7) == nil {
		t.Fatal("table not installed")
	}
	// A second refresh inside the TTL does not rebuild.
	x.refresh(context.Background(), map[uint32]uint32{7: 4242})
	select {
	case <-built:
		t.Fatal("rebuilt a fresh table")
	case <-time.After(50 * time.Millisecond):
	}
}

// Through the Decoder with a fake /proc: the real python3.12 in the fake rootfs is
// hashed via /proc/4242/exe and classified against an injected table.
func TestDecodeExecUsesBinaryIdentity(t *testing.T) {
	pyHash := sumOf([]byte("#!")) // fakeProc writes "#!" into usr/bin/python3.12
	run := func(t *testing.T, tbl *imageTable) Target {
		d, _ := testDecoder(t)
		d.Images = newImageIndex(d.ProcRoot, nil)
		if tbl != nil {
			d.Images.setTable(4026532001, tbl)
		}
		k := base(evExec)
		k.Ret, k.Path = 0, "python3"
		ev, ok := d.Decode(k)
		if !ok {
			t.Fatal("not decoded")
		}
		return ev.Facts.Target
	}
	t.Run("name matches content", func(t *testing.T) {
		tg := run(t, &imageTable{byHash: map[string]string{pyHash: "python3.12"}})
		if tg.BinaryClass != "INTERPRETER" || tg.BinaryDetail != "INTERPRETER" || tg.Renamed || tg.ForeignBinary {
			t.Fatalf("%+v", tg)
		}
		if tg.ExeSHA256 != pyHash || tg.ExeSize != 2 || tg.ExeIno == 0 {
			t.Fatalf("%+v", tg)
		}
	})
	t.Run("content is really curl", func(t *testing.T) {
		tg := run(t, &imageTable{byHash: map[string]string{pyHash: "curl"}})
		if tg.BinaryClass != "NET_CLIENT" || tg.BinaryDetail != "RENAMED:curl" || !tg.Renamed || tg.ForeignBinary {
			t.Fatalf("%+v", tg)
		}
	})
	t.Run("content unknown to the image", func(t *testing.T) {
		tg := run(t, &imageTable{byHash: map[string]string{sumOf([]byte("curl")): "curl"}})
		if tg.BinaryClass != "OTHER" || tg.BinaryDetail != "UNKNOWN_BINARY" || !tg.ForeignBinary || tg.Renamed {
			t.Fatalf("%+v", tg)
		}
	})
	t.Run("no table yet", func(t *testing.T) {
		tg := run(t, nil)
		if tg.BinaryClass != "INTERPRETER" || tg.BinaryDetail != "INTERPRETER:NAME_ONLY" || tg.ExeSHA256 != pyHash {
			t.Fatalf("%+v", tg)
		}
	})
	t.Run("failed exec is name-only without hash fields", func(t *testing.T) {
		d, _ := testDecoder(t)
		d.Images = newImageIndex(d.ProcRoot, nil)
		k := base(evExec)
		k.Ret, k.Path = -13, "/usr/bin/curl"
		ev, _ := d.Decode(k)
		tg := ev.Facts.Target
		if tg.BinaryClass != "NET_CLIENT" || tg.BinaryDetail != "NET_CLIENT" || tg.ExeSHA256 != "" {
			t.Fatalf("%+v", tg)
		}
	})
	t.Run("json carries the new fields", func(t *testing.T) {
		d, _ := testDecoder(t)
		d.Images = newImageIndex(d.ProcRoot, nil)
		d.Images.setTable(4026532001, &imageTable{byHash: map[string]string{pyHash: "curl"}})
		k := base(evExec)
		k.Ret, k.Path = 0, "python3"
		ev, _ := d.Decode(k)
		js := mustJSON(t, ev)
		for _, w := range []string{`"exe_sha256":"` + pyHash + `"`, `"exe_dev":`, `"exe_ino":`, `"exe_size":2`, `"renamed":true`, `"binary_detail":"RENAMED:curl"`} {
			if !strings.Contains(js, w) {
				t.Fatalf("missing %s in %s", w, js)
			}
		}
		if strings.Contains(js, "foreign_binary") {
			t.Fatal("omitempty false flag emitted")
		}
	})
}
