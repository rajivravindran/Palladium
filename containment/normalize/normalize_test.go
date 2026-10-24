package normalize

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

const cid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func setup(t *testing.T) (*Normalizer, *adapter.Mock, registry.Sensor, time.Time) {
	t.Helper()
	reg, err := registry.Load(filepath.Join("..", "fixtures", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := adapter.NewMock()
	m.Add(cid, "generation-1", adapter.Running)
	s, _ := reg.Authenticate("dev-sensor-token")
	return &Normalizer{Registry: registry.NewHolder(reg), Adapter: m}, m, s, time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
}

func decoy(id string) Raw {
	return Raw{Facts: RawFacts{ID: id, Sensor: "lab-sensor", Kind: "file_open", Outcome: "success",
		Workload: RawWorkload{ID: "worker-01", ContainerID: cid},
		Target:   RawTarget{Path: "/opt/config/.db_recovery_creds", PathResolved: true, Access: "read"}}}
}

func TestFullyTrustedEvent(t *testing.T) {
	n, _, s, now := setup(t)
	res, err := n.Normalize(context.Background(), Envelope{Raw: decoy("e1"), Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Context
	if !c.IdentityVerified || !c.SensorAuthenticated || !c.ResourceVerified || !c.Healthy || !c.Active || !c.DedicatedContainer {
		t.Fatalf("%+v notes=%v", c, res.Notes)
	}
	if c.Identity.TenantID != "lab" || c.Identity.ContainerID != cid || c.Identity.Generation != "generation-1" {
		t.Fatalf("%+v", c.Identity)
	}
	if res.Event.Operation != policy.FileOpen || !res.Event.OpenRead || res.Event.OpenWrite || res.Event.Outcome != policy.Succeeded {
		t.Fatalf("%+v", res.Event)
	}
	if len(res.Notes) != 0 {
		t.Fatal(res.Notes)
	}
}

func TestEventCannotClaimTrust(t *testing.T) {
	n, _, s, now := setup(t)
	// A sensor event that names another tenant/host or asserts "enrolled" changes nothing.
	raw := decoy("e2")
	raw.Facts.Workload.Enrolled = true
	raw.Facts.Workload.Profile = "some-other-profile"
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Workload.Profile != "diagnostic-worker" || res.Context.Identity.TenantID != "lab" {
		t.Fatalf("event influenced trusted context: %+v", res.Context)
	}
}

func TestContainerMismatchBreaksIdentity(t *testing.T) {
	n, _, s, now := setup(t)
	raw := decoy("e3")
	raw.Facts.Workload.ContainerID = strings.Repeat("f", 64)
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Context.IdentityVerified || !hasNote(res.Notes, "differs from enrollment") {
		t.Fatalf("%+v %v", res.Context, res.Notes)
	}
}

func TestRuntimeGenerationChangeBreaksIdentity(t *testing.T) {
	n, m, s, now := setup(t)
	m.Replace(cid, "generation-2")
	res, _ := n.Normalize(context.Background(), Envelope{Raw: decoy("e4"), Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Context.IdentityVerified || res.Context.Healthy {
		t.Fatalf("%+v", res.Context)
	}
}

func TestPausedContainerIsNotActive(t *testing.T) {
	n, m, s, now := setup(t)
	m.Add(cid, "generation-1", adapter.Paused)
	res, _ := n.Normalize(context.Background(), Envelope{Raw: decoy("e5"), Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if !res.Context.IdentityVerified || res.Context.Active {
		t.Fatalf("%+v", res.Context)
	}
}

func TestUnauthenticatedSensorNeverVerifiesResource(t *testing.T) {
	n, _, _, now := setup(t)
	res, _ := n.Normalize(context.Background(), Envelope{Raw: decoy("e6"), Authentic: false, ReceivedAt: now, Provenance: policy.Historical}, now)
	if res.Context.SensorAuthenticated || res.Context.ResourceVerified {
		t.Fatalf("%+v", res.Context)
	}
}

func TestPathTrust(t *testing.T) {
	n, _, s, now := setup(t)
	cases := map[string]struct {
		path     string
		resolved bool
		caps     bool
		want     bool
	}{
		"resolved by capable sensor": {"/opt/x", true, true, true},
		"not resolved":               {"/opt/x", false, true, false},
		"sensor lacks capability":    {"/opt/x", true, false, false},
		"relative path":              {"opt/x", true, true, false},
		"traversal":                  {"/opt/../etc/shadow", true, true, false},
		"deleted marker":             {"/opt/x (deleted)", true, true, false},
		"control character":          {"/opt/x\n", true, true, false},
		"backslash":                  {"/opt\\x", true, true, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := decoy("p")
			raw.Facts.Target.Path, raw.Facts.Target.PathResolved = tc.path, tc.resolved
			sensor := s
			sensor.ResolvesPaths = tc.caps
			res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: sensor, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
			if res.Context.ResourceVerified != tc.want {
				t.Fatalf("verified=%v notes=%v", res.Context.ResourceVerified, res.Notes)
			}
		})
	}
}

func TestExecClassComesFromController(t *testing.T) {
	n, _, s, now := setup(t)
	raw := decoy("x")
	raw.Facts.Kind = "process_exec"
	raw.Facts.Target = RawTarget{Exe: "/usr/bin/curl", BinaryClass: "DIAGNOSTIC"}
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "NET_CLIENT" || !res.Context.ResourceVerified {
		t.Fatalf("%+v", res.Event)
	}
	if !hasNote(res.Notes, "overridden") {
		t.Fatal(res.Notes)
	}
	// renamed binary: classified OTHER, honestly
	raw.Facts.Target = RawTarget{Exe: "/tmp/totally-not-curl"}
	res, _ = n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "OTHER" {
		t.Fatal(res.Event.BinaryClass)
	}
}

func TestNetConnect(t *testing.T) {
	n, _, s, now := setup(t)
	raw := decoy("x")
	raw.Facts.Kind, raw.Facts.Outcome = "net_connect", "pending"
	raw.Facts.Target = RawTarget{IP: "::ffff:203.0.113.9", Port: 443}
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.Operation != policy.NetConnect || res.Event.Outcome != policy.Attempted || !res.Context.ResourceVerified {
		t.Fatalf("%+v %+v", res.Event, res.Context)
	}
	raw.Facts.Target.IP = "not-an-ip"
	res, _ = n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Context.ResourceVerified {
		t.Fatal("unparseable destination verified")
	}
}

func TestSensorClockIsBounded(t *testing.T) {
	n, _, s, now := setup(t)
	raw := decoy("t")
	raw.Facts.Received = uint64(now.Add(-3 * time.Second).UnixNano())
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if !res.Event.ObservedAt.Equal(now.Add(-3 * time.Second)) {
		t.Fatal(res.Event.ObservedAt)
	}
	raw.Facts.Received = uint64(now.Add(time.Hour).UnixNano()) // sensor clock far ahead
	res, _ = n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if !res.Event.ObservedAt.Equal(now) || !hasNote(res.Notes, "implausible") {
		t.Fatal(res.Event.ObservedAt, res.Notes)
	}
}

func TestUnknownKindIsAnError(t *testing.T) {
	n, _, s, now := setup(t)
	raw := decoy("k")
	raw.Facts.Kind = "memory_read"
	if _, err := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now}, now); err == nil {
		t.Fatal("unsupported kind accepted")
	}
}

func TestStaleHeartbeatIsUnhealthy(t *testing.T) {
	n, _, s, now := setup(t)
	n.HeartbeatWithin = 10 * time.Second
	n.SetHeartbeat(func(string) time.Time { return now.Add(-time.Minute) })
	res, _ := n.Normalize(context.Background(), Envelope{Raw: decoy("h"), Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Context.Healthy {
		t.Fatal("stale sensor counted as healthy")
	}
}

func hasNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

const curlHash = "3f786850e387550fdab836ed7e6dc881de23001b7a0e6d6a8b8f0a4f3c5d6e7f"

func execRaw(exe, class, detail, sha string) Raw {
	raw := decoy("x")
	raw.Facts.Kind = "process_exec"
	raw.Facts.Target = RawTarget{Exe: exe, PathResolved: true, BinaryClass: class, BinaryDetail: detail, ExeSHA256: sha, ExeSize: 4, ExeDev: 1, ExeIno: 2}
	return raw
}

func TestExecClassFromSensorHashIsTrusted(t *testing.T) {
	n, _, s, now := setup(t)
	// `cp /usr/bin/curl /tmp/python3 && /tmp/python3 ...`: the sensor hashed the file
	// and found curl's content under a name the image never gave it.
	raw := execRaw("/tmp/python3", "NET_CLIENT", "RENAMED:curl", curlHash)
	raw.Facts.Target.Renamed = true
	res, err := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Event.BinaryClass != "NET_CLIENT" || !res.Context.ResourceVerified {
		t.Fatalf("%+v notes=%v", res.Event, res.Notes)
	}
	if !hasNote(res.Notes, "class from exe hash (sensor): NET_CLIENT; name would be INTERPRETER") || hasNote(res.Notes, "overridden") {
		t.Fatal(res.Notes)
	}
	tg := res.Facts["target"].(map[string]any)
	if tg["binary_class"] != "NET_CLIENT" || tg["binary_detail"] != "RENAMED:curl" || tg["exe_sha256"] != curlHash || tg["renamed"] != true {
		t.Fatalf("%v", tg)
	}
	// Same hash, name agrees: trusted, nothing to note.
	res, _ = n.Normalize(context.Background(), Envelope{Raw: execRaw("/usr/bin/curl", "NET_CLIENT", "NET_CLIENT", curlHash), Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "NET_CLIENT" || len(res.Notes) != 0 {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
	// A downloaded binary the image does not contain.
	raw = execRaw("/tmp/python3", "OTHER", "UNKNOWN_BINARY", curlHash)
	raw.Facts.Target.ForeignBinary = true
	res, _ = n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "OTHER" || !hasNote(res.Notes, "name would be INTERPRETER") || res.Facts["target"].(map[string]any)["foreign_binary"] != true {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
}

func TestExecWithoutHashKeepsNameOverride(t *testing.T) {
	n, _, s, now := setup(t)
	// No exe_sha256 (old sensor, Falco): the controller's name table wins, as before.
	raw := execRaw("/tmp/python3", "NET_CLIENT", "NET_CLIENT", "")
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "INTERPRETER" || !hasNote(res.Notes, "sensor class NET_CLIENT overridden by controller table (INTERPRETER)") {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
	if _, ok := res.Facts["target"].(map[string]any)["exe_sha256"]; ok {
		t.Fatal("hash reported without one")
	}
}

func TestExecHashTrustNeedsCapableSensorAndSaneValues(t *testing.T) {
	n, _, s, now := setup(t)
	raw := execRaw("/tmp/python3", "NET_CLIENT", "RENAMED:curl", curlHash)
	// Sensor not enrolled with resolves_paths: the hash is not evidence from it.
	weak := s
	weak.ResolvesPaths = false
	res, _ := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: weak, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "INTERPRETER" || !hasNote(res.Notes, "not trusted to identify binaries") || !hasNote(res.Notes, "overridden") {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
	// Unauthenticated channel.
	res, _ = n.Normalize(context.Background(), Envelope{Raw: raw, Authentic: false, ReceivedAt: now, Provenance: policy.Historical}, now)
	if res.Event.BinaryClass != "INTERPRETER" {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
	// Malformed hash.
	bad := execRaw("/tmp/python3", "NET_CLIENT", "RENAMED:curl", "not-a-hash")
	res, _ = n.Normalize(context.Background(), Envelope{Raw: bad, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "INTERPRETER" || !hasNote(res.Notes, "malformed") {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
	// A class outside the engine vocabulary never reaches the engine.
	bad = execRaw("/tmp/python3", "ROOTKIT", "RENAMED:curl", curlHash)
	res, _ = n.Normalize(context.Background(), Envelope{Raw: bad, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "INTERPRETER" || !hasNote(res.Notes, "not an engine class") {
		t.Fatalf("%+v %v", res.Event, res.Notes)
	}
	// A detail that is not a label is not copied into the incident.
	bad = execRaw("/tmp/python3", "NET_CLIENT", "RENAMED:curl; drop table", curlHash)
	res, _ = n.Normalize(context.Background(), Envelope{Raw: bad, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.BinaryClass != "NET_CLIENT" || res.Facts["target"].(map[string]any)["binary_detail"] != "INTERPRETER" {
		t.Fatalf("%+v %v", res.Facts["target"], res.Notes)
	}
	// The strict decoder accepts every new field river3d emits.
	line := []byte(`{"facts":{"id":"e","sensor":"ebpf","kind":"process_exec","outcome":"success","workload":{"id":"worker-01"},"process":{"pid":1},"target":{"exe":"/tmp/python3","path_resolved":true,"binary_class":"NET_CLIENT","binary_detail":"RENAMED:curl","exe_sha256":"` + curlHash + `","exe_dev":64769,"exe_ino":1234,"exe_size":4,"renamed":true,"foreign_binary":false}},"payload":{}}`)
	var r Raw
	if err := policy.DecodeStrict(line, &r); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedOutcomeIsFailedWithInlineNote(t *testing.T) {
	n, _, s, now := setup(t)
	raw := decoy("e-blocked")
	raw.Facts.Outcome = "blocked"
	res, err := n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Event.Outcome != policy.Failed {
		t.Fatalf("blocked must reach the engine as FAILED, got %s", res.Event.Outcome)
	}
	if len(res.Notes) != 1 || res.Notes[0] != BlockedNote {
		t.Fatalf("notes %v", res.Notes)
	}
	if res.Facts["blocked_inline"] != true || res.Facts["sensor_outcome"] != "blocked" || res.Facts["outcome"] != "FAILED" {
		t.Fatalf("facts %v", res.Facts)
	}
	// Trust flags are unaffected: the sensor still saw a real, kernel-resolved decoy open.
	if !res.Context.IdentityVerified || !res.Context.ResourceVerified {
		t.Fatalf("%+v", res.Context)
	}
	// The unrecognised path still exists for anything outside the vocabulary.
	raw.Facts.Outcome = "denied"
	res, _ = n.Normalize(context.Background(), Envelope{Raw: raw, Sensor: s, Authentic: true, ReceivedAt: now, Provenance: policy.Live}, now)
	if res.Event.Outcome != policy.UnknownOutcome || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "unrecognised") {
		t.Fatalf("%s %v", res.Event.Outcome, res.Notes)
	}
}
