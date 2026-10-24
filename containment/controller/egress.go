package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	policy "river3.local/policy"
)

// Domain egress (CONTRACTS.md §5).
//
// The engine matches destination IPs against egress_allowed only; it validates
// egress_allowed_domains but never consults them. The controller closes the gap by
// forward resolution: each name in a profile's EgressDomains() is looked up (A and
// AAAA) when a profile set is compiled and again every -egress-refresh, and the
// addresses become /32 and /128 prefixes appended to a COPY of that profile's
// EgressAllow. The engine is rebuilt from the derived copies and swapped in through
// the same atomic path policy sync uses. The original profile bodies are never
// touched: Policy.Profiles stays the API's bundle, so policy sync status, the
// revision and the incident's profile facts still describe what the admin wrote.
//
// What this does and does not mean: an IP is IN_SCOPE for a name if the name resolved
// to it within the last refresh, from this node's resolver. A CDN that rotates faster
// than the refresh, a split-horizon answer the workload sees but the node does not,
// or a resolver that lies all produce a VIOLATION for a connection the admin meant to
// allow (never the reverse: an address the resolver never returned is never let in).
// A wildcard "*.example.com" is resolved for the apex "example.com" only.

// Resolver is the DNS dependency; net.DefaultResolver satisfies it, tests inject a fake.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Egress holds the resolved addresses per apex name and the policy they decorate.
type Egress struct {
	Resolver Resolver      // nil = net.DefaultResolver
	Timeout  time.Duration // per name; default 3 s
	Log      *slog.Logger

	mu          sync.Mutex
	addrs       map[string][]netip.Addr // apex → last good answer (kept across failures)
	failing     map[string]string       // apex → last error, logged once until it resolves again
	capped      map[string]bool         // profiles whose derived list hit the engine's 128-CIDR limit (logged once)
	refreshedAt time.Time
	lookups     int
}

// DefaultEgressTimeout is the per-name resolution budget.
const DefaultEgressTimeout = 3 * time.Second

// maxEgressCIDRs mirrors the engine's limit on egress_allowed (policy.compile:
// "too many CIDRs"). A derived list is capped here so the engine never refuses a
// set that was valid as written.
const maxEgressCIDRs = 128

// apex strips a wildcard prefix: "*.example.com" → "example.com".
func apex(name string) string {
	return strings.TrimPrefix(name, "*.")
}

// domainsOf collects the distinct apex names across a profile set, sorted.
func domainsOf(profiles map[string]*policy.Profile) []string {
	seen := map[string]bool{}
	for _, p := range profiles {
		for _, d := range p.EgressDomains() {
			seen[apex(d)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Resolve looks every name up once (A and AAAA, Timeout each) and records the
// answers. A failure keeps the name's previous addresses and is logged on the first
// failure only; a later success logs the recovery. It returns whether any name's
// address set changed.
func (e *Egress) Resolve(ctx context.Context, names []string) bool {
	if e == nil {
		return false
	}
	e.init()
	res := e.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = DefaultEgressTimeout
	}
	changed := false
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		got, err := res.LookupNetIP(lctx, "ip", name)
		cancel()
		var note func()
		e.mu.Lock()
		e.lookups++
		if err != nil {
			if _, already := e.failing[name]; !already {
				e.failing[name] = err.Error()
				prev := len(e.addrs[name])
				note = func() {
					e.log().Warn("egress.resolve_failed", "name", name, "err", err.Error(), "kept_addresses", prev)
				}
			}
		} else {
			clean := normalizeAddrs(got)
			if _, wasFailing := e.failing[name]; wasFailing {
				delete(e.failing, name)
				note = func() { e.log().Info("egress.resolve_recovered", "name", name, "addresses", len(clean)) }
			}
			if !sameAddrs(e.addrs[name], clean) {
				e.addrs[name] = clean
				changed = true
			}
		}
		e.mu.Unlock()
		if note != nil {
			note()
		}
	}
	e.mu.Lock()
	e.refreshedAt = time.Now().UTC()
	e.mu.Unlock()
	return changed
}

func (e *Egress) init() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.addrs == nil {
		e.addrs = map[string][]netip.Addr{}
		e.failing = map[string]string{}
		e.capped = map[string]bool{}
	}
}

func (e *Egress) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// normalizeAddrs drops what cannot be a connect target, unmaps 4-in-6, dedupes, sorts.
func normalizeAddrs(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Prefixes returns the host prefixes (/32, /128) currently known for the given
// domains (wildcards by apex), sorted and deduplicated.
func (e *Egress) Prefixes(domains []string) []string {
	if e == nil {
		return nil
	}
	e.init()
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, d := range domains {
		for _, a := range e.addrs[apex(d)] {
			p := netip.PrefixFrom(a, a.BitLen()).String()
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Derive builds the enforced Policy for base: the same Profiles and Revision, an
// engine compiled from copies whose EgressAllow carries the resolved prefixes, and
// the derived prefix table (Policy.Egress) for status and change detection. The
// original profile values are not modified. If the derived set does not compile
// (it should always: the inputs are valid prefixes under the engine's cap) the base
// engine is kept and the error logged, so a resolver can never leave the node
// without policy.
func (e *Egress) Derive(base *Policy) *Policy {
	if e == nil || base == nil {
		return base
	}
	names := make([]string, 0, len(base.Profiles))
	for n := range base.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	derived := make([]policy.Profile, 0, len(names))
	table := map[string][]string{}
	var key strings.Builder
	for _, n := range names {
		orig := base.Profiles[n]
		cp := *orig // shallow copy; only EgressAllow is replaced below, never written through
		add := e.Prefixes(orig.EgressDomains())
		if len(add) > 0 {
			have := map[string]bool{}
			for _, s := range orig.EgressAllow {
				have[s] = true
			}
			merged := append([]string{}, orig.EgressAllow...)
			added := make([]string, 0, len(add))
			for _, p := range add {
				if have[p] {
					continue
				}
				if len(merged) >= maxEgressCIDRs {
					e.mu.Lock()
					first := !e.capped[n]
					e.capped[n] = true
					e.mu.Unlock()
					if first {
						e.log().Warn("egress.capped", "profile", n, "note", fmt.Sprintf("resolved addresses exceed the engine's %d-CIDR limit; the rest are left out of scope", maxEgressCIDRs))
					}
					break
				}
				merged = append(merged, p)
				added = append(added, p)
			}
			cp.EgressAllow = merged
			table[n] = added
			key.WriteString(n + ":" + strings.Join(added, ",") + ";")
		}
		derived = append(derived, cp)
	}
	out := &Policy{Engine: base.Engine, Profiles: base.Profiles, Revision: base.Revision, Egress: table, egressKey: key.String()}
	if len(table) == 0 {
		return out // no domain resolved to anything: the base engine is exactly right
	}
	eng, err := policy.NewEngine(derived, policy.Options{})
	if err != nil {
		e.log().Error("egress.derive_failed", "err", err.Error(), "note", "keeping the engine without resolved domains")
		out.Egress, out.egressKey = nil, ""
		return out
	}
	out.Engine = eng
	return out
}

// Status is what /healthz reports.
func (e *Egress) Status() map[string]any {
	if e == nil {
		return nil
	}
	e.init()
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make([]string, 0, len(e.addrs))
	addrs := 0
	for n, a := range e.addrs {
		names = append(names, n)
		addrs += len(a)
	}
	sort.Strings(names)
	failing := make([]string, 0, len(e.failing))
	for n := range e.failing {
		failing = append(failing, n)
	}
	sort.Strings(failing)
	out := map[string]any{"names": names, "addresses": addrs, "failing": failing, "lookups": e.lookups}
	if !e.refreshedAt.IsZero() {
		out["refreshed_at"] = e.refreshedAt.Format(time.RFC3339)
	}
	return out
}

// ---------------------------------------------------------------- controller side

// ApplyPolicy is SetPolicy for a set that may name egress domains: new names are
// resolved first (bounded by Egress.Timeout each) so the swapped-in engine already
// knows their addresses, then the derived engine is stored. Policy sync and the
// daemon's startup go through here; SetPolicy alone derives from whatever is cached.
func (c *Controller) ApplyPolicy(ctx context.Context, p *Policy) {
	if c.cfg.Egress != nil {
		c.cfg.Egress.Resolve(ctx, domainsOf(p.Profiles))
	}
	c.SetPolicy(p)
}

// RefreshEgress re-resolves every domain the enforced set names and, when any
// address changed, rebuilds and swaps the engine. Nothing is swapped when the
// answers are the same, so the candidate keys (which cover the profile body) stay
// stable between an event's Evaluate and its Revalidate in the steady state.
func (c *Controller) RefreshEgress(ctx context.Context) {
	eg := c.cfg.Egress
	if eg == nil {
		return
	}
	cur := c.pol.Load()
	names := domainsOf(cur.Profiles)
	if len(names) == 0 {
		return
	}
	eg.Resolve(ctx, names)
	next := eg.Derive(cur)
	if next.egressKey == cur.egressKey {
		return
	}
	c.pol.Store(next)
	added := 0
	for _, v := range next.Egress {
		added += len(v)
	}
	c.cfg.Log.Info("egress.applied", "names", len(names), "prefixes", added, "revision", short(cur.Revision))
}

// RunEgressRefresh calls RefreshEgress every interval until ctx ends (default 60 s).
func (c *Controller) RunEgressRefresh(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.RefreshEgress(ctx)
		}
	}
}

// EgressStatus is what /healthz reports; nil when domain egress is off.
func (c *Controller) EgressStatus() map[string]any {
	if c.cfg.Egress == nil {
		return nil
	}
	st := c.cfg.Egress.Status()
	if p := c.pol.Load(); p != nil && p.Egress != nil {
		st["profiles"] = p.Egress
	}
	return st
}
