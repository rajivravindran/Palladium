package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// TestGoldenEvents writes examples/events.golden.jsonl: one event of each kind from
// every source (tracepoints, the inline LSM hooks, Falco), exactly as river3d emits
// them. The LSM lines carry the two Stage-B additions: `inline` and outcome `blocked`. containment/normalize has a test that
// strictly decodes this file, so a field added on one side without the other fails
// a test instead of a 422 in production. Regenerate with:  go test -run Golden -update
var update = os.Getenv("UPDATE_GOLDEN") != ""

func TestGoldenEvents(t *testing.T) {
	d, _ := testDecoder(t)
	var evs []Event
	open := base(evOpen)
	open.Ret, open.Path = 7, "/etc/app/settings"
	ev, _ := d.Decode(open)
	evs = append(evs, ev)
	exec := base(evExec)
	exec.Ret, exec.Path, exec.Args = 0, "python3", []string{"python3", "-c", "import os"}
	ev, _ = d.Decode(exec)
	evs = append(evs, ev)
	conn := base(evConnect)
	conn.Ret, conn.Family, conn.Port = -115, 2, 0x5000
	copy(conn.Addr[:], []byte{203, 0, 113, 9})
	ev, _ = d.Decode(conn)
	evs = append(evs, ev)
	// Inline (LSM) events: a blocked decoy open, an allowed exec, an allowed connect.
	ib := inlineBase(evOpen)
	ib.Ret, ib.Path = -1, "/opt/config/.db_recovery_creds"
	ev, _ = d.Decode(ib)
	ev.Facts.Workload.Team = "payments"
	evs = append(evs, ev)
	ie := inlineBase(evExec)
	ie.Ret, ie.Path = 0, "/usr/bin/python3.12"
	ev, _ = d.Decode(ie)
	evs = append(evs, ev)
	ic := inlineBase(evConnect)
	ic.Ret, ic.Family, ic.Port = 0, 2, 0x0900
	copy(ic.Addr[:], []byte{127, 0, 0, 1})
	ev, _ = d.Decode(ic)
	evs = append(evs, ev)
	fa := &FalcoAdapter{Sensor: "falco", Watch: falcoWatch()}
	for _, line := range []string{falcoOpen, falcoExec, falcoConnect} {
		a, _ := parseFalco([]byte(line))
		ev, ok := fa.Map(a)
		if !ok {
			t.Fatal("falco fixture did not map")
		}
		evs = append(evs, ev)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	const path = "examples/events.golden.jsonl"
	if update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_GOLDEN=1 to create it)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Fatal("river3d event shape changed: review the diff, then UPDATE_GOLDEN=1 go test -run Golden, and re-run containment's tests")
	}
}
