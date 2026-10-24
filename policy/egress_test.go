package policy

import (
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEgressRuleGrammar(t *testing.T) {
	long := strings.Repeat("a", 63)
	pfx := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	valid := []struct {
		in   string
		want EgressRule
	}{
		{"10.0.0.0/8", EgressRule{Prefix: pfx("10.0.0.0/8")}},
		{"192.0.2.7/32", EgressRule{Prefix: pfx("192.0.2.7/32")}},
		{"10.0.0.0/8:443", EgressRule{Prefix: pfx("10.0.0.0/8"), PortLow: 443, PortHigh: 443}},
		{"10.0.0.0/8:8000-8100", EgressRule{Prefix: pfx("10.0.0.0/8"), PortLow: 8000, PortHigh: 8100}},
		{"10.0.0.0/8:1-65535", EgressRule{Prefix: pfx("10.0.0.0/8"), PortLow: 1, PortHigh: 65535}},
		{"2001:db8::/32", EgressRule{Prefix: pfx("2001:db8::/32")}},
		{"[2001:db8::/32]:443", EgressRule{Prefix: pfx("2001:db8::/32"), PortLow: 443, PortHigh: 443}},
		{"[2001:db8::1/128]:8000-8100", EgressRule{Prefix: pfx("2001:db8::1/128"), PortLow: 8000, PortHigh: 8100}},
		{"api.example.com", EgressRule{Host: "api.example.com"}},
		{"api.example.com:443", EgressRule{Host: "api.example.com", PortLow: 443, PortHigh: 443}},
		{"api.example.com:8000-8100", EgressRule{Host: "api.example.com", PortLow: 8000, PortHigh: 8100}},
		{"*.example.com", EgressRule{Host: "example.com", Wildcard: true}},
		{"*.github.com:443", EgressRule{Host: "github.com", Wildcard: true, PortLow: 443, PortHigh: 443}},
		{"xn--bcher-kva.example", EgressRule{Host: "xn--bcher-kva.example"}},
		{"a1.b2:65535", EgressRule{Host: "a1.b2", PortLow: 65535, PortHigh: 65535}},
		{long + ".example", EgressRule{Host: long + ".example"}},
	}
	for _, tc := range valid {
		got, err := ParseEgressRule(tc.in)
		if err != nil {
			t.Errorf("%q rejected: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	invalid := []struct{ in, reason string }{
		{"", "empty"},
		{" 10.0.0.0/8", "whitespace"},
		{"10.0.0.0/8 ", "whitespace"},
		{"bad", "at least two labels"},
		{"localhost:443", "at least two labels"},
		{"300.0.0.0/8", "not a valid CIDR"},
		{"10.0.0.0/33", "not a valid CIDR"},
		{"10.0.0.0/", "not a valid CIDR"},
		{"10.0.0.0/8/24", "not a valid CIDR"},
		{"10.2.3.4/8", "host bits; did you mean 10.0.0.0/8"},
		{"::ffff:10.0.0.0/104", "IPv4-mapped"},
		{"10.0.0.1", "CIDR form, e.g. 10.0.0.1/32"},
		{"10.0.0.1:443", "CIDR form, e.g. 10.0.0.1/32"},
		{"2001:db8::1", "IPv6 address goes in CIDR form"},
		{"2001:db8::1:443", "IPv6 address goes in CIDR form"},
		{"2001:db8::/32:443", "bracket an IPv6 CIDR before adding a port: [2001:db8::/32]:443"},
		{"[2001:db8::/32]", "brackets are only needed to add a port"},
		{"[2001:db8::/32", "missing ']'"},
		{"[2001:db8::/32]443", "expected ':port' after ']'"},
		{"[2001:db8::/32]:", "missing port"},
		{"[10.0.0.0/8]:443", "brackets must contain an IPv6 CIDR"},
		{"[example.com]:443", "brackets must contain an IPv6 CIDR"},
		{"[2001:db8::1]:443", "brackets must contain an IPv6 CIDR"},
		{"2001:db8::/32]", "brackets must open with '['"},
		{"[2001:db8::1/32]:443", "host bits"},
		{"10.0.0.0/8:", "missing port"},
		{"10.0.0.0/8:0", "1-65535"},
		{"10.0.0.0/8:70000", "1-65535"},
		{"10.0.0.0/8:0443", "no leading zeros"},
		{"10.0.0.0/8:https", "1-65535"},
		{"10.0.0.0/8:-443", "1-65535"},
		{"10.0.0.0/8:443-", "low-high"},
		{"10.0.0.0/8:443-x", "low-high"},
		{"10.0.0.0/8:8100-8000", "reversed; write 8000-8100"},
		{"10.0.0.0/8:443-443", "single port, 443"},
		{"10.0.0.0/8:80-443-8080", "low-high"},
		{"api.example.com:", "missing port"},
		{"api.example.com:0", "1-65535"},
		{"api.example.com:70000", "1-65535"},
		{"api.example.com:8100-8000", "reversed"},
		{"api.example.com:443:1", "only one ':'"},
		{"https://api.example.com", "schemes"},
		{"http://api.example.com:443", "schemes"},
		{"api.example.com/path", "paths and prefix lengths are not allowed on hostnames"},
		{"api.example.com/32", "paths and prefix lengths are not allowed on hostnames"},
		{"api.example.com?x=1", "paths are not allowed"},
		{"api.example.com#f", "paths are not allowed"},
		{"Api.Example.com", "lowercase"},
		{"api.example.com.", "trailing dot"},
		{"*.", "wildcard needs a hostname after '*.'"},
		{"*", "'*' is only allowed as the leading '*.' label"},
		{"*.:443", "wildcard needs a hostname"},
		{"*example.com", "'*' is only allowed as the leading '*.' label"},
		{"**.example.com", "'*' is only allowed as the leading '*.' label"},
		{"a.*.example.com", "'*' is only allowed as the leading '*.' label"},
		{"*.com", "at least two labels"},
		{"-bad.example.com", "start or end with '-'"},
		{"bad-.example.com", "start or end with '-'"},
		{"ex_ample.com", "only a-z, 0-9"},
		{"exa mple.com", "whitespace"},
		{"example..com", "1–63"},
		{".example.com", "1–63"},
		{long + "a.example", "1–63"},
		{strings.Repeat(long+".", 4) + "example", "253"},
		{strings.Repeat("a", 301), "too long"},
		{"example.123", "last label cannot be numeric"},
		{"1.2.3.4.5", "last label cannot be numeric"},
	}
	for _, tc := range invalid {
		_, err := ParseEgressRule(tc.in)
		if err == nil {
			t.Errorf("%q accepted", tc.in)
			continue
		}
		if !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%q: error %q does not mention %q", tc.in, err, tc.reason)
		}
	}
}

func TestEgressRuleHelpers(t *testing.T) {
	r, _ := ParseEgressRule("*.example.com:443")
	if !r.IsHost() || !r.HasPort() {
		t.Fatal(r)
	}
	r, _ = ParseEgressRule("10.0.0.0/8")
	if r.IsHost() || r.HasPort() {
		t.Fatal(r)
	}
	p := &Profile{EgressAllow: []string{"10.0.0.0/8:443", "api.example.com:443", "api.example.com:80", "*.cdn.example.net", "nonsense:x"}}
	if got := p.EgressHosts(); len(got) != 2 || got[0] != "api.example.com" || got[1] != "*.cdn.example.net" {
		t.Fatal(got)
	}
	if (*Profile)(nil).EgressHosts() != nil || (&Profile{}).EgressHosts() != nil {
		t.Fatal("nil cases")
	}
}

// netEvent is the fixture's event re-aimed at a destination.
func netEvent(v Event, ip string, port uint16, host string) Event {
	v.Operation = NetConnect
	v.Path = ""
	v.OpenRead = false
	v.DestinationIP = ip
	v.Port = port
	v.DestHost = host
	return v
}

func TestEgressMatching(t *testing.T) {
	rules := []string{
		"10.0.0.0/8:443",
		"10.0.0.0/8:8000-8100",
		"192.0.2.0/24",
		"[2001:db8::/32]:443",
		"api.example.com:443",
		"*.github.com:443",
		"files.example.net",
	}
	for _, tc := range []struct {
		name       string
		ip         string
		port       uint16
		host       string
		want       Status
		wantDetail string
	}{
		// CIDR with a single port
		{"cidr port match", "10.1.2.3", 443, "", InScope, ""},
		{"cidr port other", "10.1.2.3", 444, "", Violation, "host_unknown"},
		{"cidr port unknown", "10.1.2.3", 0, "", Violation, "host_unknown"},
		// CIDR with a range
		{"range low edge", "10.1.2.3", 8000, "", InScope, ""},
		{"range high edge", "10.1.2.3", 8100, "", InScope, ""},
		{"range inside", "10.1.2.3", 8050, "", InScope, ""},
		{"range below", "10.1.2.3", 7999, "", Violation, "host_unknown"},
		{"range above", "10.1.2.3", 8101, "", Violation, "host_unknown"},
		// CIDR without a port accepts any port, known or not
		{"any port known", "192.0.2.9", 65535, "", InScope, ""},
		{"any port unknown", "192.0.2.9", 0, "", InScope, ""},
		// IPv4-mapped IPv6 unmaps before matching and in the detail
		{"mapped match", "::ffff:10.1.2.3", 443, "", InScope, ""},
		{"mapped miss", "::ffff:11.1.2.3", 443, "", Violation, "host_unknown"},
		// IPv6 CIDR with a port; the detail brackets the address
		{"v6 match", "2001:db8::1", 443, "", InScope, ""},
		{"v6 wrong port", "2001:db8::1", 80, "", Violation, "host_unknown"},
		{"v6 outside", "2001:db9::1", 443, "", Violation, "host_unknown"},
		// Hostname rules need DestHost and ignore the IP
		{"host match", "203.0.113.5", 443, "api.example.com", InScope, ""},
		{"host wrong port", "203.0.113.5", 80, "api.example.com", Violation, "203.0.113.5:80"},
		{"host port unknown", "203.0.113.5", 0, "api.example.com", Violation, "203.0.113.5"},
		{"host other name", "203.0.113.5", 443, "evil.example.com", Violation, "203.0.113.5:443"},
		{"host without port rule", "203.0.113.5", 12345, "files.example.net", InScope, ""},
		{"host without port rule, port unknown", "203.0.113.5", 0, "files.example.net", InScope, ""},
		{"no host known", "203.0.113.5", 443, "", Violation, "host_unknown"},
		{"no host known, port unknown", "203.0.113.5", 0, "", Violation, "host_unknown"},
		{"no host but cidr matches", "10.1.2.3", 443, "", InScope, ""},
		// Wildcards: one or more labels below the apex, never the apex
		{"wildcard one label", "140.82.112.3", 443, "api.github.com", InScope, ""},
		{"wildcard two labels", "140.82.112.3", 443, "objects.api.github.com", InScope, ""},
		{"wildcard apex", "140.82.112.3", 443, "github.com", Violation, "140.82.112.3:443"},
		{"wildcard lookalike", "140.82.112.3", 443, "notgithub.com", Violation, "140.82.112.3:443"},
		{"wildcard other tld", "140.82.112.3", 443, "api.github.community", Violation, "140.82.112.3:443"},
		{"wildcard wrong port", "140.82.112.3", 80, "api.github.com", Violation, "140.82.112.3:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, p, v, c := fixture(t)
			p.EgressAllow = rules
			e, err := NewEngine([]Profile{p}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			d := evaluate(t, e, netEvent(v, tc.ip, tc.port, tc.host), c)
			if d.Status != tc.want {
				t.Fatalf("status %s, want %s: %+v", d.Status, tc.want, d)
			}
			if tc.want == Violation {
				if d.Findings[0].Code != "EGRESS_OUTSIDE_SCOPE" || d.Findings[0].Rule != tc.wantDetail {
					t.Fatalf("finding %+v, want detail %q", d.Findings[0], tc.wantDetail)
				}
			} else if len(d.Findings) != 0 {
				t.Fatal(d.Findings)
			}
		})
	}
}

// Without hostname rules the detail is the destination, never "host_unknown".
func TestEgressPortRulesWithoutHostRules(t *testing.T) {
	rules := []string{"10.0.0.0/8:443", "10.0.0.0/8:8000-8100", "[2001:db8::/32]:443"}
	for _, tc := range []struct {
		ip         string
		port       uint16
		want       Status
		wantDetail string
	}{
		{"10.1.2.3", 443, InScope, ""},
		{"10.1.2.3", 444, Violation, "10.1.2.3:444"},
		{"10.1.2.3", 0, Violation, "10.1.2.3"},
		{"10.1.2.3", 7999, Violation, "10.1.2.3:7999"},
		{"10.1.2.3", 8101, Violation, "10.1.2.3:8101"},
		{"::ffff:10.1.2.3", 8050, InScope, ""},
		{"::ffff:11.1.2.3", 443, Violation, "11.1.2.3:443"},
		{"2001:db8::1", 443, InScope, ""},
		{"2001:db8::1", 80, Violation, "[2001:db8::1]:80"},
		{"2001:db9::1", 443, Violation, "[2001:db9::1]:443"},
		{"2001:db9::1", 0, Violation, "2001:db9::1"},
	} {
		_, p, v, c := fixture(t)
		p.EgressAllow = rules
		e, err := NewEngine([]Profile{p}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		d := evaluate(t, e, netEvent(v, tc.ip, tc.port, ""), c)
		if d.Status != tc.want {
			t.Fatalf("%s:%d status %s: %+v", tc.ip, tc.port, d.Status, d)
		}
		if tc.want == Violation && d.Findings[0].Rule != tc.wantDetail {
			t.Fatalf("%s:%d detail %q, want %q", tc.ip, tc.port, d.Findings[0].Rule, tc.wantDetail)
		}
	}
}

// Plain-CIDR profiles keep their pre-B4 behaviour, and the detail is never
// "host_unknown" when no hostname rule exists.
func TestEgressDetailWithoutHostRules(t *testing.T) {
	e, _, v, c := fixture(t) // 10.0.0.0/8, 2001:db8::/32
	d := evaluate(t, e, netEvent(v, "11.0.0.1", 0, ""), c)
	if d.Findings[0].Rule != "11.0.0.1" {
		t.Fatal(d.Findings)
	}
	d = evaluate(t, e, netEvent(v, "11.0.0.1", 443, ""), c)
	if d.Findings[0].Rule != "11.0.0.1:443" {
		t.Fatal(d.Findings)
	}
	// A host the sensor resolved does not widen a CIDR-only profile.
	d = evaluate(t, e, netEvent(v, "11.0.0.1", 443, "api.example.com"), c)
	if d.Status != Violation || d.Findings[0].Rule != "11.0.0.1:443" {
		t.Fatal(d)
	}
	// Port and host are irrelevant to a bare CIDR match.
	if d := evaluate(t, e, netEvent(v, "10.0.0.1", 443, "whatever.example.com"), c); d.Status != InScope {
		t.Fatal(d)
	}
}

func TestEventPortAndHostValidation(t *testing.T) {
	e, _, v, c := fixture(t)
	for _, host := range []string{"Api.Example.com", "example.com.", "10.0.0.1", "2001:db8::1", "*.example.com", "localhost", "ex ample.com", "example.com:443", "https://example.com", "a..b"} {
		if _, err := e.Evaluate(netEvent(v, "10.0.0.1", 443, host), c); err == nil {
			t.Errorf("DestHost %q accepted", host)
		}
	}
	for _, host := range []string{"", "api.example.com", "a.b", "xn--bcher-kva.example"} {
		if _, err := e.Evaluate(netEvent(v, "10.0.0.1", 443, host), c); err != nil {
			t.Errorf("DestHost %q rejected: %v", host, err)
		}
	}
	// Port and DestHost are NET_CONNECT fields only.
	fo := v
	fo.Port = 443
	if _, err := e.Evaluate(fo, c); err == nil {
		t.Error("port accepted on FILE_OPEN")
	}
	fo = v
	fo.DestHost = "api.example.com"
	if _, err := e.Evaluate(fo, c); err == nil {
		t.Error("dest_host accepted on FILE_OPEN")
	}
	pe := v
	pe.Operation, pe.Path, pe.OpenRead, pe.BinaryClass, pe.Port = ProcessExec, "", false, "DIAGNOSTIC", 443
	if _, err := e.Evaluate(pe, c); err == nil {
		t.Error("port accepted on PROCESS_EXEC")
	}
}

func TestEventDecodeStrictPortAndHost(t *testing.T) {
	base := `{"id":"e","identity":{"tenant_id":"t","asset_id":"a","host_id":"h","generation":"g"},"observed_at":"2026-10-19T00:00:00Z","provenance":"LIVE","operation":"NET_CONNECT","outcome":"SUCCEEDED","destination_ip":"10.0.0.1"`
	var v Event
	if err := DecodeStrict([]byte(base+`}`), &v); err != nil || v.Port != 0 || v.DestHost != "" {
		t.Fatal(err, v)
	}
	if err := DecodeStrict([]byte(base+`,"port":443,"dest_host":"api.example.com"}`), &v); err != nil || v.Port != 443 || v.DestHost != "api.example.com" {
		t.Fatal(err, v)
	}
	for _, extra := range []string{`,"port":70000`, `,"port":-1`, `,"port":"443"`, `,"port":443.5`, `,"dest_host":1`, `,"port":1,"PORT":2`} {
		if err := DecodeStrict([]byte(base+extra+`}`), &v); err == nil {
			t.Errorf("%s accepted", extra)
		}
	}
}

func TestEgressProfilesLoadStrictly(t *testing.T) {
	ok := `{"name":"x","kind":"ai_worker","egress_allowed":["10.0.0.0/8","10.0.0.0/8:443","10.0.0.0/8:8000-8100","[2001:db8::/32]:443","api.example.com:443","*.github.com"]}`
	ps, err := ParseProfiles([]Document{{Source: "ok", Data: []byte(ok)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ps["x"].EgressHosts(); len(got) != 2 || got[0] != "api.example.com" || got[1] != "*.github.com" {
		t.Fatal(got)
	}
	for name, bad := range map[string]string{
		"too many":   `{"name":"x","kind":"ai_worker","egress_allowed":[` + strings.Repeat(`"10.0.0.0/8",`, 128) + `"192.0.2.0/24"]}`,
		"scheme":     `{"name":"x","kind":"ai_worker","egress_allowed":["https://api.example.com"]}`,
		"ip as host": `{"name":"x","kind":"ai_worker","egress_allowed":["10.0.0.1:443"]}`,
		"port zero":  `{"name":"x","kind":"ai_worker","egress_allowed":["10.0.0.0/8:0"]}`,
		"reversed":   `{"name":"x","kind":"ai_worker","egress_allowed":["api.example.com:443-80"]}`,
		"v6 port":    `{"name":"x","kind":"ai_worker","egress_allowed":["2001:db8::/32:443"]}`,
		"wildcard":   `{"name":"x","kind":"ai_worker","egress_allowed":["*."]}`,
	} {
		if _, err := ParseProfiles([]Document{{Source: name, Data: []byte(bad)}}); err == nil {
			t.Errorf("%s accepted", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error does not name the document: %v", name, err)
		}
	}
	// 128 entries exactly is still fine.
	max := `{"name":"x","kind":"ai_worker","egress_allowed":[` + strings.Repeat(`"10.0.0.0/8",`, 127) + `"192.0.2.0/24"]}`
	if _, err := ParseProfiles([]Document{{Source: "max", Data: []byte(max)}}); err != nil {
		t.Fatal(err)
	}
}

// The shipped examples stay loadable, and api-agent.json demonstrates every B4 form.
func TestExampleProfilesLoad(t *testing.T) {
	ps, err := LoadProfiles("examples/profiles")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"diagnostic-worker", "payment-service", "api-agent"} {
		if ps[name] == nil {
			t.Fatalf("example %q missing", name)
		}
	}
	if got := ps["api-agent"].EgressHosts(); len(got) != 2 || got[0] != "api.openai.com" || got[1] != "*.github.com" {
		t.Fatal(got)
	}
	e, err := NewEngine([]Profile{*ps["api-agent"]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, v, c := fixture(t)
	c.ProfileName = "api-agent"
	for _, tc := range []struct {
		ip   string
		port uint16
		host string
		want Status
		rule string
	}{
		{"140.82.112.3", 443, "api.github.com", InScope, ""},
		{"140.82.112.3", 443, "github.com", Violation, "140.82.112.3:443"},
		{"140.82.112.3", 443, "", Violation, "host_unknown"},
		{"10.20.1.1", 8080, "", InScope, ""},
		{"10.20.1.1", 8101, "", Violation, "host_unknown"},
		{"192.0.2.53", 0, "", InScope, ""},
		{"2001:db8::10", 443, "", InScope, ""},
	} {
		d := evaluate(t, e, netEvent(v, tc.ip, tc.port, tc.host), c)
		if d.Status != tc.want || (tc.rule != "" && d.Findings[0].Rule != tc.rule) {
			t.Fatalf("%+v: %+v", tc, d)
		}
	}
}

// Egress evaluation on the in-scope path must not allocate beyond what it did before B4
// (the Decision's empty Findings/Blockers slices). Hostname and port matching add nothing.
func TestEgressMatchDoesNotAllocate(t *testing.T) {
	rules := []EgressRule{}
	for _, s := range []string{"10.0.0.0/8:443", "[2001:db8::/32]:8000-8100", "api.example.com:443", "*.github.com:443", "files.example.net"} {
		r, err := ParseEgressRule(s)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, r)
	}
	addr := netip.MustParseAddr("140.82.112.3")
	host := "objects.api.github.com"
	allocs := testing.AllocsPerRun(1000, func() {
		hit := false
		for i := range rules {
			if rules[i].matches(addr, 443, host) {
				hit = true
				break
			}
		}
		if !hit || !validDestHost(host) {
			t.Fatal("expected a wildcard match")
		}
	})
	if allocs != 0 {
		t.Fatalf("matching allocated %.1f times per run", allocs)
	}
}

func FuzzEgressRule(f *testing.F) {
	for _, s := range []string{"10.0.0.0/8", "10.0.0.0/8:443", "10.0.0.0/8:8000-8100", "[2001:db8::/32]:443", "2001:db8::/32",
		"api.example.com", "*.example.com:443", "10.0.0.1:443", "*.", "[", "]", "a.b:1-", "example.com:65536", "::ffff:10.0.0.0/104"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseEgressRule(s)
		if err != nil {
			if r != (EgressRule{}) {
				t.Fatal("non-zero rule with error")
			}
			return
		}
		// Invariants of an accepted rule.
		if r.IsHost() == r.Prefix.IsValid() {
			t.Fatalf("%q: exactly one of host/prefix must be set: %+v", s, r)
		}
		if r.PortLow > r.PortHigh || (r.PortLow == 0) != (r.PortHigh == 0) {
			t.Fatalf("%q: bad port bounds %+v", s, r)
		}
		if r.IsHost() {
			if !utf8.ValidString(r.Host) || strings.ContainsAny(r.Host, "*:/[] ") || strings.ToLower(r.Host) != r.Host || !strings.Contains(r.Host, ".") || checkHostname(r.Host) != nil {
				t.Fatalf("%q: malformed host %+v", s, r)
			}
			// The apex never matches its own wildcard; a subdomain always matches.
			if r.Wildcard && r.matches(netip.Addr{}, r.PortLow, r.Host) {
				t.Fatalf("%q: wildcard matched the apex", s)
			}
			if !r.matches(netip.Addr{}, r.PortLow, map[bool]string{true: "x." + r.Host, false: r.Host}[r.Wildcard]) {
				t.Fatalf("%q: rule does not match its own name", s)
			}
			if r.PortLow != 0 && r.matches(netip.Addr{}, 0, "x."+r.Host) {
				t.Fatalf("%q: port rule matched an unknown port", s)
			}
		} else {
			if r.Prefix != r.Prefix.Masked() || r.Prefix.Addr().Is4In6() {
				t.Fatalf("%q: unmasked or mapped prefix %+v", s, r)
			}
			if !r.matches(r.Prefix.Addr(), r.PortLow, "") {
				t.Fatalf("%q: prefix does not match its own network address", s)
			}
		}
		// Round trip: an accepted entry that is written back from its parts is accepted again.
		var back string
		if r.IsHost() {
			if r.Wildcard {
				back = "*."
			}
			back += r.Host
		} else if r.Prefix.Addr().Is6() && r.PortLow != 0 {
			back = "[" + r.Prefix.String() + "]"
		} else {
			back = r.Prefix.String()
		}
		if r.PortLow != 0 {
			back += ":" + itoa(int(r.PortLow))
			if r.PortHigh != r.PortLow {
				back += "-" + itoa(int(r.PortHigh))
			}
		}
		if again, err := ParseEgressRule(back); err != nil || again != r {
			t.Fatalf("%q -> %q: %v %+v", s, back, err, again)
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
