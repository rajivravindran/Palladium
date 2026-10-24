package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t testing.TB) (*Engine, Profile, Event, Context) {
	t.Helper()
	p := Profile{Name: "diagnostic", Kind: "ai_worker", Version: 1, Mode: Active, Decoys: []string{"/opt/config/.db_recovery_creds"}, ProtectRead: []string{"/root/.aws/**"}, ReadAllow: []string{"/var/log/app/**", "/etc/app/**"}, WriteAllow: []string{"/tmp/work/**"}, ExecAllow: []string{"DIAGNOSTIC"}, ExecDeny: []string{"NET_CLIENT"}, EgressAllow: []string{"10.0.0.0/8", "2001:db8::/32"}, Response: ResponsePolicy{Pause, Pause}}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	id := Identity{TenantID: "tenant-a", AssetID: "worker-a", HostID: "node-a", Generation: "boot-1-container-1", ContainerID: strings.Repeat("a", 64), SessionID: "session-1"}
	v := Event{ID: "event-1", Identity: id, ObservedAt: now.Add(-time.Second), Provenance: Live, Operation: FileOpen, Outcome: Succeeded, Path: "/opt/config/.db_recovery_creds", OpenRead: true}
	ctx := Context{ProfileName: p.Name, ProfileVersion: p.Version, Identity: id, Now: now, IdentityVerified: true, SensorAuthenticated: true, ResourceVerified: true, Healthy: true, Active: true, DedicatedContainer: true, PermittedActions: []Action{Pause, Revoke}, AdapterActions: []Action{Pause, Revoke}}
	e, err := NewEngine([]Profile{p}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e, p, v, ctx
}
func evaluate(t testing.TB, e *Engine, v Event, c Context) Decision {
	t.Helper()
	d, err := e.Evaluate(v, c)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDecoyProducesCandidateNotResult(t *testing.T) {
	e, _, v, c := fixture(t)
	d := evaluate(t, e, v, c)
	if d.Status != Violation || d.Action != Pause || d.Candidate == nil {
		t.Fatalf("%+v", d)
	}
	if d.Findings[0].Code != "DECOY_OPEN" {
		t.Fatal(d.Findings)
	}
	if err := e.Revalidate(*d.Candidate, v, c); err != nil {
		t.Fatal(err)
	}
}
func TestContainmentGates(t *testing.T) {
	cases := []struct {
		name, block string
		mutate      func(*Event, *Context)
	}{
		{"historical", "NON_LIVE_EVIDENCE", func(v *Event, c *Context) { v.Provenance = Historical }},
		{"simulation", "NON_LIVE_EVIDENCE", func(v *Event, c *Context) { v.Provenance = Simulation }},
		{"failed", "OUTCOME_NOT_SUCCESSFUL", func(v *Event, c *Context) { v.Outcome = Failed }},
		{"attempted", "OUTCOME_NOT_SUCCESSFUL", func(v *Event, c *Context) { v.Outcome = Attempted }},
		{"unknown outcome", "OUTCOME_NOT_SUCCESSFUL", func(v *Event, c *Context) { v.Outcome = UnknownOutcome }},
		{"forged identity", "IDENTITY_NOT_VERIFIED", func(v *Event, c *Context) { c.IdentityVerified = false }},
		{"wrong tenant", "IDENTITY_NOT_VERIFIED", func(v *Event, c *Context) { v.Identity.TenantID = "tenant-b" }},
		{"stale generation", "IDENTITY_NOT_VERIFIED", func(v *Event, c *Context) { c.Identity.Generation = "new-generation" }},
		{"different session", "IDENTITY_NOT_VERIFIED", func(v *Event, c *Context) { c.Identity.SessionID = "session-2" }},
		{"untrusted sensor", "UNAUTHENTICATED_SENSOR", func(v *Event, c *Context) { c.SensorAuthenticated = false }},
		{"unverified symlink", "RESOURCE_NOT_VERIFIED", func(v *Event, c *Context) { c.ResourceVerified = false }},
		{"stale event", "STALE_EVENT", func(v *Event, c *Context) { v.ObservedAt = c.Now.Add(-time.Minute) }},
		{"future event", "FUTURE_EVENT", func(v *Event, c *Context) { v.ObservedAt = c.Now.Add(time.Minute) }},
		{"no time", "MISSING_CONTROLLER_TIME", func(v *Event, c *Context) { c.Now = time.Time{} }},
		{"disabled workload", "WORKLOAD_NOT_READY", func(v *Event, c *Context) { c.Active = false }},
		{"sensor gap", "WORKLOAD_NOT_READY", func(v *Event, c *Context) { c.Healthy = false }},
		{"shared container", "NOT_A_DEDICATED_BOUND_CONTAINER", func(v *Event, c *Context) { c.DedicatedContainer = false }},
		{"missing permission", "ACTION_NOT_PERMITTED", func(v *Event, c *Context) { c.PermittedActions = nil }},
		{"missing adapter", "ADAPTER_UNAVAILABLE", func(v *Event, c *Context) { c.AdapterActions = nil }},
		{"wrong policy version", "POLICY_VERSION_MISMATCH", func(v *Event, c *Context) { c.ProfileVersion = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _, v, c := fixture(t)
			tc.mutate(&v, &c)
			d := evaluate(t, e, v, c)
			if d.Action != Alert || d.Candidate != nil || !contains(d.Blockers, tc.block) {
				t.Fatalf("%+v", d)
			}
		})
	}
}
func TestShadowNeverContains(t *testing.T) {
	_, p, v, c := fixture(t)
	p.Mode = Shadow
	e, err := NewEngine([]Profile{p}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := evaluate(t, e, v, c)
	if d.Action != Alert || d.RecommendedAction != Pause || !contains(d.Blockers, "SHADOW_MODE") {
		t.Fatal(d)
	}
}
func TestFileScopes(t *testing.T) {
	for _, tc := range []struct {
		path        string
		read, write bool
		status      Status
		code        string
	}{
		{"/var/log/app/error.log", true, false, InScope, ""},
		{"/var/log/application/error.log", true, false, Violation, "READ_OUTSIDE_SCOPE"},
		{"/etc/app/service.conf", true, false, InScope, ""},
		{"/root/.aws/credentials", true, false, Violation, "PROTECTED_OPEN"},
		{"/tmp/work/output", false, true, InScope, ""},
		{"/tmp/worker/output", false, true, Violation, "WRITE_OUTSIDE_SCOPE"},
		{"/etc/app/service.conf", true, true, Violation, "WRITE_OUTSIDE_SCOPE"},
		{"/tmp/work/../../etc/passwd", false, true, Unknown, "UNRESOLVED_FILE_OPEN"},
		{"/tmp//work/x", false, true, Unknown, "UNRESOLVED_FILE_OPEN"},
		{"/tmp/work/x (deleted)", false, true, Unknown, "UNRESOLVED_FILE_OPEN"},
		{"relative/path", true, false, Unknown, "UNRESOLVED_FILE_OPEN"},
		{"/etc/app/x", false, false, Unknown, "UNRESOLVED_FILE_OPEN"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			e, _, v, c := fixture(t)
			v.Path = tc.path
			v.OpenRead = tc.read
			v.OpenWrite = tc.write
			d := evaluate(t, e, v, c)
			if d.Status != tc.status {
				t.Fatal(d)
			}
			if tc.code != "" && d.Findings[0].Code != tc.code {
				t.Fatal(d)
			}
		})
	}
}
func TestReadAllowAbsentVersusEmpty(t *testing.T) {
	for _, tc := range []struct {
		allow []string
		want  Status
	}{{nil, InScope}, {[]string{}, Violation}} {
		_, p, v, c := fixture(t)
		p.ReadAllow = tc.allow
		v.Path = "/any/ordinary/file"
		e, err := NewEngine([]Profile{p}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if d := evaluate(t, e, v, c); d.Status != tc.want {
			t.Fatal(d)
		}
	}
}
func TestDecoyOverridesAllowedRead(t *testing.T) {
	_, p, v, c := fixture(t)
	p.ReadAllow = []string{"/**"}
	e, _ := NewEngine([]Profile{p}, Options{})
	if d := evaluate(t, e, v, c); d.Action != Pause {
		t.Fatal(d)
	}
}
func TestExecDenyOverridesAllow(t *testing.T) {
	_, p, v, c := fixture(t)
	p.ExecAllow = append(p.ExecAllow, "NET_CLIENT")
	e, _ := NewEngine([]Profile{p}, Options{})
	v.Operation = ProcessExec
	v.Path = ""
	v.OpenRead = false
	v.BinaryClass = "NET_CLIENT"
	d := evaluate(t, e, v, c)
	if d.Action != Pause || d.Findings[0].Code != "EXEC_CLASS_DENIED" {
		t.Fatal(d)
	}
	v.BinaryClass = "cat"
	d = evaluate(t, e, v, c)
	if d.Status != Unknown || d.Candidate != nil {
		t.Fatal(d)
	}
}
func TestEgress(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want Status
	}{{"10.2.3.4", InScope}, {"::ffff:10.2.3.4", InScope}, {"2001:db8::1", InScope}, {"11.0.0.1", Violation}, {"::ffff:11.0.0.1", Violation}, {"example.com", Unknown}, {"10.0.0.1:443", Unknown}, {"fe80::1%eth0", Unknown}, {"0.0.0.0", Unknown}} {
		t.Run(tc.ip, func(t *testing.T) {
			e, _, v, c := fixture(t)
			v.Operation = NetConnect
			v.Path = ""
			v.OpenRead = false
			v.DestinationIP = tc.ip
			d := evaluate(t, e, v, c)
			if d.Status != tc.want {
				t.Fatal(d)
			}
		})
	}
}
func TestEmptyEgressDeniesOutbound(t *testing.T) {
	_, p, v, c := fixture(t)
	p.EgressAllow = nil
	e, _ := NewEngine([]Profile{p}, Options{})
	v.Operation = NetConnect
	v.Path = ""
	v.OpenRead = false
	v.DestinationIP = "127.0.0.1"
	if d := evaluate(t, e, v, c); d.Status != Violation {
		t.Fatal(d)
	}
}

// A domain in egress_allowed_domains never allows a connection by itself: the engine
// matches IPs only. The controller must resolve the name and add the address to
// egress_allowed before the connection is in scope.
func TestEgressDomainsAreNotMatched(t *testing.T) {
	_, p, v, c := fixture(t)
	p.EgressAllow = nil
	p.EgressAllowDomains = []string{"example.com", "*.example.net"}
	e, err := NewEngine([]Profile{p}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Operation = NetConnect
	v.Path = ""
	v.OpenRead = false
	for _, ip := range []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		v.DestinationIP = ip
		d := evaluate(t, e, v, c)
		if d.Status != Violation || d.Findings[0].Code != "EGRESS_OUTSIDE_SCOPE" {
			t.Fatalf("%s: %+v", ip, d)
		}
	}
	// Once the controller has resolved the name into a prefix, the same IP is in scope.
	p.EgressAllow = []string{"93.184.216.34/32"}
	e, _ = NewEngine([]Profile{p}, Options{})
	v.DestinationIP = "93.184.216.34"
	if d := evaluate(t, e, v, c); d.Status != InScope {
		t.Fatal(d)
	}
}

func TestEgressDomainValidation(t *testing.T) {
	long := strings.Repeat("a", 63)
	valid := []string{
		"example.com", "*.example.com", "localhost", "api.v2.example-site.co.uk", "xn--bcher-kva.example",
		"a1.b2", long + ".example", strings.TrimSuffix(strings.Repeat(long+".", 3)+strings.Repeat("b", 61), "."),
	}
	for _, d := range valid {
		if err := validateDomain(d); err != nil {
			t.Errorf("%q rejected: %v", d, err)
		}
	}
	invalid := []string{
		"", "Example.com", "example.com.", "10.0.0.1", "2001:db8::1", "[2001:db8::1]", "example.com:443",
		"https://example.com", "example.com/path", "example.com?x=1", "-bad.example.com", "bad-.example.com",
		"*.", "*", "a.*.example.com", "**.example.com", "*example.com", "exa mple.com", "ex_ample.com",
		"example..com", ".example.com", long + "a.example", strings.Repeat(long+".", 4) + "example",
	}
	for _, d := range invalid {
		if err := validateDomain(d); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestEgressDomainsLoadedStrictlyAndExposed(t *testing.T) {
	dir := t.TempDir()
	raw := `{"name":"x","kind":"ai_worker","egress_allowed":["10.0.0.0/8"],"egress_allowed_domains":["api.example.com","*.cdn.example.net"]}`
	if err := os.WriteFile(filepath.Join(dir, "p.json"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := ps["x"].EgressDomains()
	if len(got) != 2 || got[0] != "api.example.com" || got[1] != "*.cdn.example.net" {
		t.Fatal(got)
	}
	got[0] = "changed"
	if ps["x"].EgressAllowDomains[0] != "api.example.com" {
		t.Fatal("accessor returned the backing slice")
	}
	if (*Profile)(nil).EgressDomains() != nil {
		t.Fatal("nil profile")
	}
	for name, bad := range map[string]string{
		"too many":  `{"name":"x","kind":"ai_worker","egress_allowed_domains":[` + strings.Repeat(`"a.example",`, 128) + `"b.example"]}`,
		"ip":        `{"name":"x","kind":"ai_worker","egress_allowed_domains":["10.0.0.1"]}`,
		"port":      `{"name":"x","kind":"ai_worker","egress_allowed_domains":["example.com:443"]}`,
		"scheme":    `{"name":"x","kind":"ai_worker","egress_allowed_domains":["https://example.com"]}`,
		"uppercase": `{"name":"x","kind":"ai_worker","egress_allowed_domains":["Example.com"]}`,
		"dot":       `{"name":"x","kind":"ai_worker","egress_allowed_domains":["example.com."]}`,
	} {
		if _, err := ParseProfiles([]Document{{Source: name, Data: []byte(bad)}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSharedServiceOnlyScopedRevoke(t *testing.T) {
	_, p, v, c := fixture(t)
	p.Kind = "shared_service"
	if _, err := NewEngine([]Profile{p}, Options{}); err == nil {
		t.Fatal("shared pause accepted")
	}
	p.Response = ResponsePolicy{Revoke, Alert}
	e, err := NewEngine([]Profile{p}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Identity.ContainerID = ""
	c.Identity = v.Identity
	c.DedicatedContainer = false
	d := evaluate(t, e, v, c)
	if d.Action != Revoke {
		t.Fatal(d)
	}
	c.Identity.SessionID = ""
	v.Identity = c.Identity
	d = evaluate(t, e, v, c)
	if d.Action != Alert || !contains(d.Blockers, "NO_BOUND_SESSION") {
		t.Fatal(d)
	}
}
func TestStructuralGuardCannotRevoke(t *testing.T) {
	// A verified Channel A model verdict may at most pause a dedicated worker. REVOKE_SESSION on
	// on_structural_guard is refused at compile time, while it stays valid on on_violation.
	_, p, _, _ := fixture(t)
	p.Response = ResponsePolicy{OnViolation: Pause, OnStructuralGuard: Revoke}
	_, err := NewEngine([]Profile{p}, Options{})
	if err == nil || !strings.Contains(err.Error(), "session revocation needs a deterministic violation") {
		t.Fatalf("structural guard revoke accepted: %v", err)
	}
	p.Response = ResponsePolicy{OnViolation: Revoke, OnStructuralGuard: Pause}
	if _, err := NewEngine([]Profile{p}, Options{}); err != nil {
		t.Fatalf("pause on structural guard refused: %v", err)
	}
}
func TestGuardIsolationAndBinding(t *testing.T) {
	t.Run("B cannot downgrade decoy", func(t *testing.T) {
		e, _, v, c := fixture(t)
		c.Assessments = []Assessment{{v.ID, v.Identity, "B", Continue, true}}
		if d := evaluate(t, e, v, c); d.Action != Pause {
			t.Fatal(d)
		}
	})
	t.Run("A can request containment", func(t *testing.T) {
		e, _, v, c := fixture(t)
		v.Path = "/etc/app/service.conf"
		c.Assessments = []Assessment{{v.ID, v.Identity, "A", Contain, true}, {v.ID, v.Identity, "B", Continue, true}}
		if d := evaluate(t, e, v, c); d.Action != Pause {
			t.Fatal(d)
		}
	})
	t.Run("B alone alerts", func(t *testing.T) {
		e, _, v, c := fixture(t)
		v.Path = "/etc/app/service.conf"
		c.Assessments = []Assessment{{v.ID, v.Identity, "B", Contain, true}}
		if d := evaluate(t, e, v, c); d.Action != Alert || d.Candidate != nil {
			t.Fatal(d)
		}
	})
	t.Run("forged A cannot act", func(t *testing.T) {
		e, _, v, c := fixture(t)
		v.Path = "/etc/app/service.conf"
		c.Assessments = []Assessment{{v.ID, v.Identity, "A", Contain, false}}
		if d := evaluate(t, e, v, c); d.Action != Alert {
			t.Fatal(d)
		}
	})
	t.Run("wrong evidence cannot act", func(t *testing.T) {
		e, _, v, c := fixture(t)
		v.Path = "/etc/app/service.conf"
		c.Assessments = []Assessment{{"other-event", v.Identity, "A", Contain, true}}
		if d := evaluate(t, e, v, c); d.Action != Alert {
			t.Fatal(d)
		}
	})
	t.Run("duplicate channel cannot act", func(t *testing.T) {
		e, _, v, c := fixture(t)
		v.Path = "/etc/app/service.conf"
		c.Assessments = []Assessment{{v.ID, v.Identity, "A", Contain, true}, {v.ID, v.Identity, "A", Continue, true}}
		if d := evaluate(t, e, v, c); d.Action != Alert {
			t.Fatal(d)
		}
	})
	t.Run("model unavailable does not block deterministic reflex", func(t *testing.T) {
		e, _, v, c := fixture(t)
		c.Assessments = []Assessment{{v.ID, v.Identity, "A", Unavailable, true}}
		if d := evaluate(t, e, v, c); d.Action != Pause {
			t.Fatal(d)
		}
	})
}
func TestRevalidationRejectsChanges(t *testing.T) {
	for _, name := range []string{"expired", "permission", "generation", "policy", "content", "action", "key", "future lease"} {
		t.Run(name, func(t *testing.T) {
			e, p, v, c := fixture(t)
			candidate := *evaluate(t, e, v, c).Candidate
			switch name {
			case "expired":
				c.Now = candidate.ExpiresAt
			case "permission":
				c.PermittedActions = nil
			case "generation":
				c.Identity.Generation = "new"
			case "policy":
				p.Response.OnViolation = Alert
				e, _ = NewEngine([]Profile{p}, Options{})
			case "content":
				v.Path = "/root/.aws/credentials"
			case "action":
				candidate.Action = Revoke
			case "key":
				candidate.IdempotencyKey = "fake"
			case "future lease":
				candidate.IssuedAt = c.Now.Add(time.Second)
			}
			if err := e.Revalidate(candidate, v, c); err == nil {
				t.Fatal("accepted stale/tampered candidate")
			}
		})
	}
}
func TestIdempotencyStableAndScoped(t *testing.T) {
	e, _, v, c := fixture(t)
	a := evaluate(t, e, v, c).Candidate.IdempotencyKey
	c.Now = c.Now.Add(time.Second)
	b := evaluate(t, e, v, c).Candidate.IdempotencyKey
	if a != b {
		t.Fatal("retry key changed")
	}
	v.Identity.TenantID = "tenant-b"
	c.Identity = v.Identity
	if a == evaluate(t, e, v, c).Candidate.IdempotencyKey {
		t.Fatal("cross tenant collision")
	}
}
func TestProfilesAreCopiedAndConcurrent(t *testing.T) {
	_, p, v, c := fixture(t)
	e, _ := NewEngine([]Profile{p}, Options{})
	p.Decoys[0] = "/changed"
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := e.Evaluate(v, c)
			if err != nil || d.Findings[0].Code != "DECOY_OPEN" {
				t.Errorf("%+v %v", d, err)
			}
		}()
	}
	wg.Wait()
}
func TestUntrustedBenignEventIsUnknown(t *testing.T) {
	e, _, v, c := fixture(t)
	v.Path = "/etc/app/service.conf"
	c.IdentityVerified = false
	d := evaluate(t, e, v, c)
	if d.Status != Unknown || d.Action != Alert {
		t.Fatal(d)
	}
}
func TestContextCannotBeDecodedFromEventJSON(t *testing.T) {
	var c Context
	if err := json.Unmarshal([]byte(`{"IdentityVerified":true,"identity_verified":true,"ProfileName":"x"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.IdentityVerified || c.ProfileName != "" {
		t.Fatal("context populated by JSON")
	}
}
func TestInvalidEventsAndOptions(t *testing.T) {
	e, _, v, c := fixture(t)
	for _, op := range []Operation{"", "mount", "PROCESS_EXEC;podman kill"} {
		bad := v
		bad.Operation = op
		if _, err := e.Evaluate(bad, c); err == nil {
			t.Fatal(op)
		}
	}
	v.Identity.ContainerID = "abc123"
	if _, err := e.Evaluate(v, c); err == nil {
		t.Fatal("short container id accepted")
	}
	_, p, _, _ := fixture(t)
	if _, err := NewEngine([]Profile{p}, Options{ActionTTL: -1}); err == nil {
		t.Fatal("negative TTL accepted")
	}
}

func TestStrictProfileLoading(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"unknown field", `{"name":"x","kind":"ai_worker","typo":true}`},
		{"duplicate key", `{"name":"x","name":"y","kind":"ai_worker"}`},
		{"case collision", `{"name":"x","Name":"y","kind":"ai_worker"}`},
		{"bad kind", `{"name":"x","kind":"anything"}`},
		{"invalid glob", `{"name":"x","kind":"ai_worker","decoys":["/etc/["]}`},
		{"relative glob", `{"name":"x","kind":"ai_worker","decoys":["etc/*"]}`},
		{"subtree wildcard", `{"name":"x","kind":"ai_worker","decoys":["/var/*/**"]}`},
		{"bad CIDR", `{"name":"x","kind":"ai_worker","egress_allowed":["bad"]}`},
		{"CIDR host bits", `{"name":"x","kind":"ai_worker","egress_allowed":["10.2.3.4/8"]}`},
		{"mapped prefix", `{"name":"x","kind":"ai_worker","egress_allowed":["::ffff:10.0.0.0/104"]}`},
		{"two JSON objects", `{"name":"x","kind":"ai_worker"}{}`},
		{"unknown class", `{"name":"x","kind":"ai_worker","exec_allowed_classes":["cat"]}`},
		{"kill response", `{"name":"x","kind":"ai_worker","response":{"on_violation":"TERMINATE_CONTAINER"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "p.json"), []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProfiles(dir); err == nil {
				t.Fatal("bad policy accepted")
			}
		})
	}
}
func TestLoaderDefaultsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"name":"x","kind":"ai_worker"}`)
	if err := os.WriteFile(filepath.Join(dir, "a.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p["x"].Mode != Shadow || p["x"].Response.OnViolation != Alert || p["x"].Version != 1 {
		t.Fatal(p)
	}
	os.WriteFile(filepath.Join(dir, "b.json"), raw, 0600)
	if _, err = LoadProfiles(dir); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err = LoadProfiles(t.TempDir()); err == nil {
		t.Fatal("empty directory accepted")
	}
}
func TestGlobBoundaries(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{{"/**", "/anything", true}, {"/app/**", "/app", true}, {"/app/**", "/app/a/b", true}, {"/app/**", "/application", false}, {"/app/*", "/app/a/b", false}, {"/app/*.log", "/app/x.log", true}} {
		if got := globMatch(tc.pattern, tc.path); got != tc.want {
			t.Errorf("%+v = %v", tc, got)
		}
	}
}
func FuzzGlobBoundary(f *testing.F) {
	f.Add("foo")
	f.Add("/child")
	f.Fuzz(func(t *testing.T, suffix string) {
		candidate := "/allowed" + suffix
		if !canonicalPath(candidate) {
			return
		}
		if globMatch("/allowed/**", candidate) && candidate != "/allowed" && !strings.HasPrefix(candidate, "/allowed/") {
			t.Fatal("boundary bypass")
		}
	})
}
func FuzzDecodeStrict(f *testing.F) {
	f.Add([]byte(`{"name":"x","kind":"ai_worker"}`))
	f.Add([]byte(`{"name":"x","name":"y"}`))
	f.Add([]byte(`{"name":"x","kind":"ai_worker","egress_allowed_domains":["*.example.com","Example.com:443"]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		var p Profile
		_ = DecodeStrict(data, &p)
	})
}
