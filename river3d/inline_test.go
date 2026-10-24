package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Inline (LSM) events: outcome from the hook's decision, path from the kernel.

func inlineBase(typ uint32) kernelEvent {
	k := base(typ)
	k.Inline = true
	k.Dev, k.Ino = 0x800001, 4242
	return k
}

func TestInlineOpenBlockedIsBlockedNotFailed(t *testing.T) {
	d, _ := testDecoder(t)
	k := inlineBase(evOpen)
	k.Ret = -1 // -EPERM from lsm/file_open
	k.Path = "/opt/config/.db_recovery_creds"
	ev, ok := d.Decode(k)
	if !ok {
		t.Fatal("not decoded")
	}
	f := ev.Facts
	if f.Outcome != OutcomeBlocked || f.Errno != 1 || !f.Inline {
		t.Fatalf("%+v", f)
	}
	if f.Target.Path != "/opt/config/.db_recovery_creds" || !f.Target.PathResolved || f.Target.Access != "read" {
		t.Fatalf("kernel-rendered path must be taken as resolved: %+v", f.Target)
	}
	js := mustJSON(t, ev)
	for _, w := range []string{`"outcome":"blocked"`, `"errno":1`, `"inline":true`, `"kind":"file_open"`} {
		if !strings.Contains(js, w) {
			t.Fatalf("missing %s in %s", w, js)
		}
	}
}

func TestInlineOpenAllowedIsSuccess(t *testing.T) {
	d, _ := testDecoder(t)
	k := inlineBase(evOpen)
	k.Ret, k.Flags, k.Path = 0, 1, "/var/log/app/error.log"
	ev, _ := d.Decode(k)
	if ev.Facts.Outcome != OutcomeSuccess || ev.Facts.Errno != 0 || !ev.Facts.Inline || ev.Facts.Target.Access != "write" {
		t.Fatalf("%+v", ev.Facts)
	}
}

func TestInlineOpenWithoutPathFallsBackToInodeTable(t *testing.T) {
	d, _ := testDecoder(t)
	k := inlineBase(evOpen)
	k.Ret, k.Path = -1, "" // bpf_d_path failed (ENAMETOOLONG)
	ev, _ := d.Decode(k)
	if ev.Facts.Target.Path != "" || ev.Facts.Target.PathResolved {
		t.Fatalf("without a table the file must stay unnamed, not guessed: %+v", ev.Facts.Target)
	}
	b := newInodeBlocker(nil, nil, nil)
	b.paths[inodeKey{Dev: 0x800001, Ino: 4242, Mntns: 4026532001}] = "/opt/config/.db_recovery_creds"
	b.paths[inodeKey{Dev: 0x800001, Ino: 4242, Mntns: 99}] = "/other/workload/file"
	d.Inodes = b
	ev, _ = d.Decode(k)
	if ev.Facts.Target.Path != "/opt/config/.db_recovery_creds" || !ev.Facts.Target.PathResolved || ev.Facts.Outcome != OutcomeBlocked {
		t.Fatalf("%+v", ev.Facts.Target)
	}
}

func TestInlineExecUsesKernelPathNotProcExe(t *testing.T) {
	d, _ := testDecoder(t)
	// In the fixture /proc/4242/exe points at python3.12 (the caller). The LSM
	// hook reports the file about to run: a different binary.
	k := inlineBase(evExec)
	k.Ret, k.Path = 0, "/opt/config/.db_recovery_creds" // whatever file bprm->file names
	ev, _ := d.Decode(k)
	f := ev.Facts
	if f.Kind != KindProcessExec || f.Target.Exe != "/opt/config/.db_recovery_creds" || !f.Target.PathResolved || !f.Inline {
		t.Fatalf("%+v", f)
	}
	if len(ev.Payload.Argv) != 0 {
		t.Fatal("LSM exec events carry no argv")
	}
	// With the image index on, the hash comes from the named file inside the root.
	idx := newImageIndex(d.ProcRoot, nil)
	sum := sha256.Sum256([]byte("#!"))
	idx.setTable(4026532001, &imageTable{byHash: map[string]string{hex.EncodeToString(sum[:]): "python3.12"}, alias: map[string]string{"python3": "python3.12"}})
	d.Images = idx
	k.Path = "/usr/bin/python3.12"
	ev, _ = d.Decode(k)
	tg := ev.Facts.Target
	if tg.ExeSHA256 != hex.EncodeToString(sum[:]) || tg.BinaryClass != "INTERPRETER" || tg.BinaryDetail != "INTERPRETER" || tg.Renamed || tg.ForeignBinary {
		t.Fatalf("%+v", tg)
	}
	// A copy of the interpreter under another name is still RENAMED by content.
	k.Path = "/opt/config/.db_recovery_creds" // content "inert", not in the table → foreign
	ev, _ = d.Decode(k)
	if !ev.Facts.Target.ForeignBinary || ev.Facts.Target.BinaryDetail != "UNKNOWN_BINARY" {
		t.Fatalf("%+v", ev.Facts.Target)
	}
}

func TestInlineConnectAllowedIsSuccessEvenIfTCPLaterFails(t *testing.T) {
	d, _ := testDecoder(t)
	k := inlineBase(evConnect)
	k.Ret, k.Family, k.Port = 0, 2, 0x0900 // port 9 (discard), nobody listens
	copy(k.Addr[:], []byte{127, 0, 0, 1})
	ev, _ := d.Decode(k)
	f := ev.Facts
	if f.Kind != KindNetConnect || f.Outcome != OutcomeSuccess || f.Target.IP != "127.0.0.1" || f.Target.Port != 9 || !f.Inline {
		t.Fatalf("%+v", f)
	}
}

func TestTracepointEventsCarryNoInlineKey(t *testing.T) {
	d, _ := testDecoder(t)
	k := base(evOpen)
	k.Ret, k.Path = 7, "/etc/app/settings"
	ev, _ := d.Decode(k)
	if strings.Contains(mustJSON(t, ev), `"inline"`) {
		t.Fatal("inline must be omitted for tracepoint events (wire shape unchanged)")
	}
	if ev.Facts.Outcome != OutcomeSuccess {
		t.Fatal(ev.Facts.Outcome)
	}
	// A failed syscall is still "failed": only an LSM denial is "blocked".
	k.Ret = -1
	ev, _ = d.Decode(k)
	if ev.Facts.Outcome != OutcomeFailed {
		t.Fatal(ev.Facts.Outcome)
	}
}

func TestBlockedMapsToPolicyFailed(t *testing.T) {
	ev := Event{Facts: Facts{Kind: KindFileOpen, Outcome: OutcomeBlocked, Inline: true, Target: Target{Path: "/x", Access: "read"}}}
	pe, err := toPolicyEvent(ev, "t", "h")
	if err != nil || string(pe.Outcome) != "FAILED" {
		t.Fatalf("%v %+v", err, pe)
	}
}

func TestWorkloadTeamOnTheWire(t *testing.T) {
	b, _ := json.Marshal(WorkloadRef{ID: "w", Team: "payments"})
	if !strings.Contains(string(b), `"team":"payments"`) {
		t.Fatal(string(b))
	}
	b, _ = json.Marshal(WorkloadRef{ID: "w"})
	if strings.Contains(string(b), `"team"`) {
		t.Fatal("team must be omitted when empty")
	}
}
