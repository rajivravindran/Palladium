package main

// Hostname resolution for egress rules (contract §4, B4).
//
// The kernel reports a connect() to an IP; profiles may now allow egress by name
// ("api.openai.com:443"). The sensor closes the gap from its side: every hostname
// named by the loaded profiles (and by -hosts-file) is resolved periodically and the
// answers are kept in an IP → host cache. A net_connect whose destination is in the
// cache gets `facts.target.host`, which the shadow path hands the engine as
// Event.DestHost and the controller will copy once its side lands.
//
// What this is and is not. It is the sensor's forward resolution of the names the
// operator wrote down, so a connection to one of their addresses can be matched by
// name. It is not what the workload resolved: a workload that is handed a different
// answer (split-horizon DNS, a poisoned resolver) connects to an IP this cache does
// not know, the event carries no host, and a hostname-only profile yields
// EGRESS_OUTSIDE_SCOPE with `host_unknown`, which is the safe direction. Wildcard
// names (*.github.com) have no forward resolution at all and are skipped (logged
// once); matching them needs a sensor that observes the workload's own DNS traffic,
// which is planned and not this.
//
// Bounds: at most 256 names, 8 lookups in flight, 2 s per lookup, one round every
// -resolve-every (60 s). An entry lives -host-ttl (10 min) past the last round that
// confirmed it, so a name that stops resolving keeps its last addresses until then.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "river3.local/policy"
)

const (
	maxResolvedNames   = 256
	resolveConcurrency = 8
	resolveTimeout     = 2 * time.Second
)

// hostLookup is what the decoders need: the name for a destination IP, if known.
type hostLookup interface {
	Lookup(ip string) (string, bool)
}

// lookupFunc resolves one hostname to its addresses (net.Resolver in production).
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

type hostEntry struct {
	host    string
	expires time.Time
}

type hostResolver struct {
	lookup lookupFunc
	ttl    time.Duration
	now    func() time.Time
	log    func(string, ...any)

	mu       sync.RWMutex
	names    []string // sorted, deduplicated, validated, no wildcards
	cache    map[netip.Addr]hostEntry
	rounds   uint64
	skipped  map[string]bool // names already logged as unresolvable here (wildcards)
	failures map[string]bool // names whose last lookup failed, logged on transition
}

func newHostResolver(lookup lookupFunc, ttl time.Duration, log func(string, ...any)) *hostResolver {
	if lookup == nil {
		res := &net.Resolver{}
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			addrs, err := res.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for i := range addrs {
				addrs[i] = addrs[i].Unmap()
			}
			return addrs, nil
		}
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if log == nil {
		log = func(string, ...any) {}
	}
	return &hostResolver{lookup: lookup, ttl: ttl, now: func() time.Time { return time.Now() }, log: log,
		cache: map[netip.Addr]hostEntry{}, skipped: map[string]bool{}, failures: map[string]bool{}}
}

// SetNames replaces the name list. Names are lowercased and deduplicated; wildcards
// and malformed names are logged once and dropped; the list is cut at
// maxResolvedNames (sorted, so the cut is deterministic and logged).
func (h *hostResolver) SetNames(names []string) {
	seen := map[string]bool{}
	var keep []string
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		switch {
		case strings.HasPrefix(n, "*."):
			if !h.skipped[n] {
				h.skipped[n] = true
				h.log("resolve-hosts: %s: wildcard names cannot be resolved forward; the rule matches only through a DNS-observing sensor (planned)", n)
			}
		case !validHostname(n):
			if !h.skipped[n] {
				h.skipped[n] = true
				h.log("resolve-hosts: %q is not a hostname; skipped", n)
			}
		default:
			keep = append(keep, n)
		}
	}
	sort.Strings(keep)
	if len(keep) > maxResolvedNames {
		h.log("resolve-hosts: %d names exceed the limit of %d; the last %d (sorted) are not resolved", len(keep), maxResolvedNames, len(keep)-maxResolvedNames)
		keep = keep[:maxResolvedNames]
	}
	h.names = keep
}

// Names returns the names that will be resolved (for logging and tests).
func (h *hostResolver) Names() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]string{}, h.names...)
}

// Resolve runs one round: every name, bounded concurrency and per-lookup timeout.
// Addresses that resolved get a fresh expiry; the first name (sorted) to claim an
// address in a round names it; expired entries are then dropped.
func (h *hostResolver) Resolve(ctx context.Context) {
	names := h.Names()
	results := make([][]netip.Addr, len(names))
	errs := make([]error, len(names))
	sem := make(chan struct{}, resolveConcurrency)
	var wg sync.WaitGroup
	for i, n := range names {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n string) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, resolveTimeout)
			defer cancel()
			results[i], errs[i] = h.lookup(lctx, n)
		}(i, n)
	}
	wg.Wait()

	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	fresh := map[netip.Addr]bool{}
	for i, n := range names {
		if errs[i] != nil || len(results[i]) == 0 {
			if ctx.Err() == nil && !h.failures[n] {
				h.failures[n] = true
				h.log("resolve-hosts: %s: %v (keeping any cached addresses until they expire)", n, errOrEmpty(errs[i]))
			}
			continue
		}
		if h.failures[n] {
			delete(h.failures, n)
			h.log("resolve-hosts: %s resolves again", n)
		}
		for _, a := range results[i] {
			a = a.Unmap()
			if !a.IsValid() || fresh[a] {
				continue
			}
			fresh[a] = true
			h.cache[a] = hostEntry{host: n, expires: now.Add(h.ttl)}
		}
	}
	for a, e := range h.cache {
		if !e.expires.After(now) {
			delete(h.cache, a)
		}
	}
	h.rounds++
}

func errOrEmpty(err error) error {
	if err == nil {
		return errors.New("no addresses")
	}
	return err
}

// Lookup implements hostLookup: the cached name for ip, when present and unexpired.
func (h *hostResolver) Lookup(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	h.mu.RLock()
	e, ok := h.cache[a]
	h.mu.RUnlock()
	if !ok || !e.expires.After(h.now()) {
		return "", false
	}
	return e.host, true
}

// Size is the number of cached addresses (unexpired or not yet purged).
func (h *hostResolver) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.cache)
}

// Run resolves immediately and then every `every` until ctx ends.
func (h *hostResolver) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	h.Resolve(ctx)
	h.mu.RLock()
	h.log("resolve-hosts: first round done: %d name(s), %d address(es) cached", len(h.names), len(h.cache))
	h.mu.RUnlock()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Resolve(ctx)
		}
	}
}

// ---------------------------------------------------------------------------
// where the names come from
// ---------------------------------------------------------------------------

// validHostname accepts what the engine accepts as Event.DestHost: a lowercase DNS
// name of at least two labels of [a-z0-9-] (1–63 chars, no leading or trailing '-'),
// at most 253 characters, a non-numeric last label, no wildcard, not an IP literal.
// Kept in step with policy's checkHostname/validDestHost so a resolved name is never
// one the engine rejects the whole event for.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "*:/ ") || strings.HasSuffix(s, ".") || !strings.Contains(s, ".") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// hostOfEgressRule extracts the hostname from one -hosts-file line, which may use the
// §4 egress grammar ("host", "host:443", "*.host:443", "10.0.0.0/8", "10.0.0.0/8:8000-8100")
// so a profile's list can be pasted as is. CIDR and IP rules yield "" (nothing to
// resolve); SetNames validates the rest and logs wildcards once.
func hostOfEgressRule(rule string) string {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return ""
	}
	if _, err := netip.ParsePrefix(rule); err == nil {
		return ""
	}
	if _, err := netip.ParseAddr(rule); err == nil {
		return ""
	}
	host := rule
	if i := strings.LastIndexByte(rule, ':'); i > 0 && isPortSpec(rule[i+1:]) {
		host = rule[:i]
		if _, err := netip.ParsePrefix(host); err == nil {
			return ""
		}
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			return ""
		}
	}
	return strings.ToLower(host)
}

// isPortSpec: "443" or "8000-8100".
func isPortSpec(s string) bool {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		hi = lo
	}
	for _, p := range []string{lo, hi} {
		n, err := strconv.Atoi(p)
		if err != nil || p == "" || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// hostnamesFromProfiles collects every name the profiles can match on: the hostname
// rules of egress_allowed (parsed by the engine's own grammar, wildcards included so
// they can be reported) and egress_allowed_domains.
func hostnamesFromProfiles(profiles map[string]*policy.Profile) []string {
	var out []string
	for _, p := range profiles {
		if p == nil {
			continue
		}
		out = append(out, p.EgressHosts()...)
		out = append(out, p.EgressDomains()...)
	}
	return out
}

// loadHostsFile reads a newline list of hostnames (# comments and blank lines
// skipped), for deployments that run the sensor without -shadow-profiles.
func loadHostsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		if len(out) >= maxResolvedNames {
			return nil, fmt.Errorf("%s: more than %d names", path, maxResolvedNames)
		}
		h := hostOfEgressRule(s)
		switch {
		case h == "": // a CIDR or address line: nothing to resolve, not an error
		case validHostname(h) || strings.HasPrefix(h, "*."):
			out = append(out, h)
		default:
			return nil, fmt.Errorf("%s:%d: %q is not a hostname", path, line, s)
		}
	}
	return out, sc.Err()
}
