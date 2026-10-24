package normalize

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// TestRiver3dGoldenEventsDecodeStrictly is the other half of river3d's TestGoldenEvents:
// every event the sensor emits (eBPF and Falco) must pass the controller's strict
// decoder and normalize to a fully populated policy.Event.
func TestRiver3dGoldenEventsDecodeStrictly(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "river3d", "examples", "events.golden.jsonl"))
	if err != nil {
		t.Skip("river3d golden file not alongside:", err)
	}
	defer f.Close()
	reg, err := registry.Load(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := adapter.NewMock()
	m.Add(cid, "generation-1", adapter.Running)
	n := &Normalizer{Registry: registry.NewHolder(reg), Adapter: m}
	s, _ := reg.Authenticate("dev-sensor-token")
	profiles, err := policy.LoadProfiles(filepath.Join("..", "fixtures", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	var list []policy.Profile
	for _, p := range profiles {
		list = append(list, *p)
	}
	eng, err := policy.NewEngine(list, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		var raw Raw
		if err := policy.DecodeStrict(sc.Bytes(), &raw); err != nil {
			t.Fatalf("river3d emits a field the controller does not know: %v\n%s", err, sc.Text())
		}
		now := time.Unix(0, int64(raw.Facts.Received)).UTC().Add(time.Second)
		res, err := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
		if err != nil {
			t.Fatalf("%s: %v", raw.Facts.ID, err)
		}
		if res.Event.Operation == "" || res.Event.Outcome == "" || !res.Enrolled || !res.Context.IdentityVerified {
			t.Fatalf("%s: incomplete normalization %+v notes=%v", raw.Facts.ID, res.Event, res.Notes)
		}
		switch res.Event.Operation {
		case policy.FileOpen:
			if res.Event.Path == "" || !(res.Event.OpenRead || res.Event.OpenWrite) {
				t.Fatalf("%s: %+v", raw.Facts.ID, res.Event)
			}
		case policy.ProcessExec:
			if res.Event.BinaryClass == "" {
				t.Fatalf("%s: %+v", raw.Facts.ID, res.Event)
			}
		case policy.NetConnect:
			if res.Event.DestinationIP == "" {
				t.Fatalf("%s: %+v", raw.Facts.ID, res.Event)
			}
		}
		// The engine itself must accept it (validateEvent is strict about mixed fields).
		res.WithProfileVersion(1)
		if _, err := eng.Evaluate(res.Event, res.Context); err != nil {
			t.Fatalf("%s: engine rejected normalized event: %v", raw.Facts.ID, err)
		}
		if raw.Facts.Inline {
			if !containsNote(res.Notes, InlineNote) || res.Facts["inline"] != true {
				t.Fatalf("%s: inline event not noted: %v %v", raw.Facts.ID, res.Notes, res.Facts["inline"])
			}
		}
		if raw.Facts.Workload.Team != "" {
			if res.Team != raw.Facts.Workload.Team {
				t.Fatalf("%s: team %q not carried (got %q)", raw.Facts.ID, raw.Facts.Workload.Team, res.Team)
			}
		}
		if raw.Facts.Outcome == "blocked" && (res.Event.Outcome != policy.Failed || !containsNote(res.Notes, BlockedNote)) {
			t.Fatalf("%s: blocked outcome not mapped: %+v %v", raw.Facts.ID, res.Event, res.Notes)
		}
		count++
	}
	// 3 eBPF (tracepoint) + 3 LSM (inline, one blocked, team label) + 3 Falco.
	if count != 9 {
		t.Fatalf("expected 9 golden events, got %d", count)
	}
}

func containsNote(notes []string, s string) bool {
	for _, n := range notes {
		if n == s {
			return true
		}
	}
	return false
}
