package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "river3.local/policy"
)

// fakeDNS is an injected lookup: a table of answers, a failure set, and a count of
// concurrent lookups to check the bound.
type fakeDNS struct {
	mu       sync.Mutex
	answers  map[string][]string
	failing  map[string]bool
	calls    atomic.Int32
	inflight atomic.Int32
	maxSeen  atomic.Int32
	block    time.Duration
}

func (f *fakeDNS) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		m := f.maxSeen.Load()
		if n <= m || f.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	if f.block > 0 {
		select {
		case <-time.After(f.block):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing[host] {
		return nil, errors.New("SERVFAIL")
	}
	var out []netip.Addr
	for _, a := range f.answers[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if out == nil {
		return nil, errors.New("no such host")
	}
	return out, nil
}

func (f *fakeDNS) set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.answers == nil {
		f.answers = map[string][]string{}
	}
	f.answers[host] = addrs
}

func (f *fakeDNS) fail(host string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing == nil {
		f.failing = map[string]bool{}
	}
	f.failing[host] = on
}

func TestHostResolverFillsCacheKeepsStaleAndExpires(t *testing.T) {
	dns := &fakeDNS{}
	dns.set("api.openai.com", "104.18.6.192", "2606:4700::6812:6c0")
	dns.set("hub.example.net", "10.9.8.7")
	var logs []string
	h := newHostResolver(dns.lookup, 10*time.Minute, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.SetNames([]string{"API.openai.com", "hub.example.net", "api.openai.com"})
	if got := h.Names(); len(got) != 2 || got[0] != "api.openai.com" {
		t.Fatalf("%v", got)
	}
	ctx := context.Background()
	h.Resolve(ctx)
	for ip, want := range map[string]string{"104.18.6.192": "api.openai.com", "2606:4700::6812:6c0": "api.openai.com", "10.9.8.7": "hub.example.net", "::ffff:10.9.8.7": "hub.example.net"} {
		if got, ok := h.Lookup(ip); !ok || got != want {
			t.Fatalf("%s → %q %v", ip, got, ok)
		}
	}
	if _, ok := h.Lookup("8.8.8.8"); ok {
		t.Fatal("unknown address resolved")
	}
	if _, ok := h.Lookup("not-an-ip"); ok {
		t.Fatal("garbage resolved")
	}

	// The name stops resolving: its addresses stay until the TTL runs out, logged once.
	dns.fail("hub.example.net", true)
	now = now.Add(5 * time.Minute)
	h.Resolve(ctx)
	h.Resolve(ctx)
	if got, ok := h.Lookup("10.9.8.7"); !ok || got != "hub.example.net" {
		t.Fatal("stale entry dropped before its TTL")
	}
	if n := countContaining(logs, "hub.example.net: SERVFAIL"); n != 1 {
		t.Fatalf("failure logged %d times: %v", n, logs)
	}
	// Past the TTL (10 min after the last confirming round at t=0): gone. The other
	// name was re-confirmed at t+5, so it stays.
	now = now.Add(5*time.Minute + time.Second)
	if _, ok := h.Lookup("10.9.8.7"); ok {
		t.Fatal("expired entry still answered")
	}
	h.Resolve(ctx) // purge
	if got, ok := h.Lookup("104.18.6.192"); !ok || got != "api.openai.com" {
		t.Fatal("live entry lost")
	}
	if h.Size() != 2 {
		t.Fatalf("cache size %d", h.Size())
	}
	// Address moves to another name: the new owner wins at the next round.
	dns.fail("hub.example.net", false)
	dns.set("hub.example.net", "104.18.6.192")
	h.Resolve(ctx)
	if got, _ := h.Lookup("104.18.6.192"); got != "api.openai.com" {
		t.Fatalf("shared address must go to the first name in sorted order, got %q", got)
	}
	if countContaining(logs, "resolves again") != 1 {
		t.Fatalf("%v", logs)
	}
}

func countContaining(logs []string, s string) int {
	n := 0
	for _, l := range logs {
		if strings.Contains(l, s) {
			n++
		}
	}
	return n
}

func TestHostResolverBoundsNamesConcurrencyAndTimeout(t *testing.T) {
	dns := &fakeDNS{block: 30 * time.Millisecond}
	var names []string
	for i := 0; i < maxResolvedNames+20; i++ {
		n := fmt.Sprintf("h%03d.example.org", i)
		names = append(names, n)
		dns.set(n, fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	var logs []string
	h := newHostResolver(dns.lookup, time.Minute, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	h.SetNames(names)
	if len(h.Names()) != maxResolvedNames || countContaining(logs, "exceed the limit") != 1 {
		t.Fatalf("%d names; %v", len(h.Names()), logs)
	}
	h.Resolve(context.Background())
	if dns.calls.Load() != int32(maxResolvedNames) {
		t.Fatalf("%d lookups", dns.calls.Load())
	}
	if m := dns.maxSeen.Load(); m > resolveConcurrency || m < 2 {
		t.Fatalf("concurrency observed %d", m)
	}
	if h.Size() != maxResolvedNames {
		t.Fatalf("cache %d", h.Size())
	}
	// A hanging lookup is cut at resolveTimeout and does not poison the others.
	slow := &fakeDNS{block: 10 * time.Second}
	slow.set("slow.example.org", "10.2.0.1")
	fast := &fakeDNS{}
	fast.set("fast.example.org", "10.2.0.2")
	h2 := newHostResolver(func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host == "slow.example.org" {
			return slow.lookup(ctx, host)
		}
		return fast.lookup(ctx, host)
	}, time.Minute, nil)
	h2.SetNames([]string{"slow.example.org", "fast.example.org"})
	start := time.Now()
	h2.Resolve(context.Background())
	if d := time.Since(start); d > resolveTimeout+time.Second {
		t.Fatalf("round took %s", d)
	}
	if _, ok := h2.Lookup("10.2.0.2"); !ok {
		t.Fatal("fast name lost to the slow one")
	}
	if _, ok := h2.Lookup("10.2.0.1"); ok {
		t.Fatal("timed-out lookup produced an answer")
	}
}

func TestHostResolverSkipsWildcardsAndBadNamesOnce(t *testing.T) {
	var logs []string
	h := newHostResolver((&fakeDNS{}).lookup, time.Minute, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	names := []string{"*.github.com", "api.github.com", "localhost", "10.0.0.1", "bad_host.example", "example.123", "-x.example.com", "Upper.Example.COM"}
	h.SetNames(names)
	h.SetNames(names)
	if got := h.Names(); len(got) != 2 || got[0] != "api.github.com" || got[1] != "upper.example.com" {
		t.Fatalf("%v", got)
	}
	if countContaining(logs, "*.github.com") != 1 || countContaining(logs, "wildcard") != 1 {
		t.Fatalf("%v", logs)
	}
	for _, bad := range []string{"localhost", "10.0.0.1", "bad_host.example", "example.123", "-x.example.com"} {
		if countContaining(logs, fmt.Sprintf("%q", bad)) != 1 {
			t.Fatalf("%s not logged exactly once: %v", bad, logs)
		}
	}
}

func TestValidHostnameMatchesEngineDestHostRules(t *testing.T) {
	good := []string{"api.openai.com", "a.b", "x-y.example.co.uk", "1.example.com"}
	bad := []string{"", "localhost", "example.", ".example.com", "a..b", "exa_mple.com", "*.example.com", "example.com:443", "1.2.3.4", "::1", "example.123", "-a.example.com", "a-.example.com", strings.Repeat("a", 64) + ".com", strings.Repeat("ab.", 90) + "com"}
	for _, g := range good {
		if !validHostname(g) {
			t.Errorf("%q rejected", g)
		}
	}
	for _, b := range bad {
		if validHostname(b) {
			t.Errorf("%q accepted", b)
		}
	}
}

func TestHostOfEgressRuleGrammar(t *testing.T) {
	cases := map[string]string{
		"api.openai.com":            "api.openai.com",
		"api.openai.com:443":        "api.openai.com",
		"API.OpenAI.com:8000-8100":  "api.openai.com",
		"*.github.com:443":          "*.github.com",
		"10.0.0.0/8":                "",
		"10.0.0.0/8:443":            "",
		"10.0.0.0/8:8000-8100":      "",
		"192.168.1.1":               "",
		"2001:db8::1":               "",
		"2001:db8::/32:443":         "",
		"[2001:db8::1]:443":         "",
		"":                          "",
		"   api.openai.com:443   ":  "api.openai.com",
		"host.example.com:notaport": "host.example.com:notaport", // left for validation to reject
	}
	for in, want := range cases {
		if got := hostOfEgressRule(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestHostnamesFromProfilesUsesEngineGrammar(t *testing.T) {
	profiles := map[string]*policy.Profile{
		"a": {Name: "a", EgressAllow: []string{"10.0.0.0/8", "api.openai.com:443", "*.github.com:443", "10.1.0.0/16:8000-8100"}},
		"b": {Name: "b", EgressAllow: []string{"hub.example.net"}, EgressAllowDomains: []string{"models.example.org"}},
		"c": nil,
	}
	got := hostnamesFromProfiles(profiles)
	want := map[string]bool{"api.openai.com": true, "*.github.com": true, "hub.example.net": true, "models.example.org": true}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected %q in %v", g, got)
		}
	}
	h := newHostResolver((&fakeDNS{}).lookup, time.Minute, nil)
	h.SetNames(got)
	if n := h.Names(); len(n) != 3 || n[0] != "api.openai.com" {
		t.Fatalf("%v", n)
	}
}

func TestLoadHostsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte("# names the sensor should know\napi.openai.com:443\n\nhub.example.net   # inline comment\n10.0.0.0/8\n*.github.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadHostsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "api.openai.com" || got[1] != "hub.example.net" || got[2] != "*.github.com" {
		t.Fatalf("%v", got)
	}
	_ = os.WriteFile(p, []byte("not a host name\n"), 0o600)
	if _, err := loadHostsFile(p); err == nil || !strings.Contains(err.Error(), ":1:") {
		t.Fatalf("%v", err)
	}
	var many strings.Builder
	for i := 0; i <= maxResolvedNames; i++ {
		fmt.Fprintf(&many, "h%d.example.com\n", i)
	}
	_ = os.WriteFile(p, []byte(many.String()), 0o600)
	if _, err := loadHostsFile(p); err == nil {
		t.Fatal("over-long hosts file accepted")
	}
	if _, err := loadHostsFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}

type staticHosts map[string]string

func (s staticHosts) Lookup(ip string) (string, bool) { h, ok := s[ip]; return h, ok }

func TestDecodeConnectSetsTargetHost(t *testing.T) {
	d, _ := testDecoder(t)
	d.Hosts = staticHosts{"104.18.6.192": "api.openai.com"}
	k := base(evConnect)
	k.Ret = 0
	k.Family = 2
	k.Addr = [16]byte{104, 18, 6, 192}
	k.Port = uint16(443<<8&0xffff) | 443>>8 // network byte order (0x01bb → 0xbb01)
	ev, ok := d.Decode(k)
	if !ok || ev.Facts.Target.IP != "104.18.6.192" || ev.Facts.Target.Port != 443 {
		t.Fatalf("%+v", ev.Facts.Target)
	}
	if ev.Facts.Target.Host != "api.openai.com" {
		t.Fatalf("host %q", ev.Facts.Target.Host)
	}
	k.Addr = [16]byte{10, 0, 0, 9}
	ev, _ = d.Decode(k)
	if ev.Facts.Target.Host != "" {
		t.Fatalf("unknown address got host %q", ev.Facts.Target.Host)
	}
	// Without a resolver nothing changes.
	d.Hosts = nil
	k.Addr = [16]byte{104, 18, 6, 192}
	if ev, _ := d.Decode(k); ev.Facts.Target.Host != "" {
		t.Fatal("host set without a resolver")
	}
}

func TestShadowConversionCarriesDestHostAndPort(t *testing.T) {
	ev := Event{Facts: Facts{ID: "ev-1", Kind: KindNetConnect, Outcome: OutcomeSuccess,
		Workload: WorkloadRef{ID: "worker-01", ContainerID: cidA},
		Target:   Target{IP: "104.18.6.192", Port: 443, Host: "api.openai.com"}}}
	pe, err := toPolicyEvent(ev, "t", "h")
	if err != nil {
		t.Fatal(err)
	}
	if pe.Operation != policy.NetConnect || pe.DestinationIP != "104.18.6.192" || pe.Port != 443 || pe.DestHost != "api.openai.com" {
		t.Fatalf("%+v", pe)
	}
	// The engine accepts the event with a host and matches the hostname rule.
	p := policy.Profile{Name: "egress-by-name", Kind: "ai_worker", Version: 1, Mode: policy.Shadow,
		EgressAllow: []string{"api.openai.com:443"}}
	eng, err := policy.NewEngine([]policy.Profile{p}, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pe.Identity.AssetID = "worker-01"
	pe.ObservedAt = time.Now().UTC()
	d, err := eng.Evaluate(pe, policy.Context{ProfileName: p.Name, ProfileVersion: p.Version, Now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Findings {
		if strings.Contains(fmt.Sprint(f), "EGRESS_OUTSIDE_SCOPE") {
			t.Fatalf("named host should be in scope: %+v", d)
		}
	}
	// Same connect without a host: out of scope (host_unknown).
	pe.DestHost = ""
	d2, err := eng.Evaluate(pe, policy.Context{ProfileName: p.Name, ProfileVersion: p.Version, Now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(d2.Findings), "EGRESS_OUTSIDE_SCOPE") {
		t.Fatalf("connect without a resolved host must be out of scope for a hostname-only rule: %+v", d2)
	}
}
