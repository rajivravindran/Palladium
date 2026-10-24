package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// EgressRule is one parsed egress_allowed entry (CONTRACTS §4). Exactly one of Prefix
// and Host is set. PortLow 0 means "any port"; otherwise the destination port must be
// known and inside [PortLow, PortHigh]. It is a value type and never mutated after parse.
type EgressRule struct {
	Prefix   netip.Prefix // CIDR form; zero value when Host is set
	Host     string       // hostname form, lowercase, without the leading "*."
	Wildcard bool         // Host matches any subdomain of Host, but not Host itself
	PortLow  uint16       // 0 = any port
	PortHigh uint16
}

// IsHost reports whether the rule matches by resolved hostname rather than by address.
func (r EgressRule) IsHost() bool { return r.Host != "" }

// HasPort reports whether the rule constrains the destination port.
func (r EgressRule) HasPort() bool { return r.PortLow != 0 }

// matches is the hot path. It allocates nothing: hostname comparison is done on
// slices of the event's own string, ports are integer compares.
func (r EgressRule) matches(addr netip.Addr, port uint16, host string) bool {
	if r.PortLow != 0 && (port == 0 || port < r.PortLow || port > r.PortHigh) {
		return false
	}
	if r.Host == "" {
		return r.Prefix.Contains(addr)
	}
	if host == "" {
		return false
	}
	if !r.Wildcard {
		return host == r.Host
	}
	// "*.example.com": one or more labels, then ".example.com". The apex does not match.
	n := len(host) - len(r.Host)
	return n >= 2 && host[n-1] == '.' && host[n:] == r.Host
}

// ParseEgressRule parses one egress_allowed entry:
//
//	10.0.0.0/8                  CIDR, any port
//	10.0.0.0/8:443              CIDR, one port
//	10.0.0.0/8:8000-8100        CIDR, port range (low < high)
//	2001:db8::/32               IPv6 CIDR, any port
//	[2001:db8::/32]:443         IPv6 CIDR with a port must be bracketed
//	api.example.com[:443]       exact hostname, optional port or range
//	*.example.com[:443]         any subdomain of example.com, not the apex
//
// Hostnames are lowercase RFC 1123 names (labels of a-z, 0-9, '-'; 1–63 chars each;
// at most 253 in all; the last label is not numeric). An IP address written in the
// host form is rejected: addresses always use CIDR form (/32 or /128 for one host).
// Nothing is normalised: the entry the console stores is what the engine compiles.
func ParseEgressRule(s string) (EgressRule, error) {
	bad := func(reason string) (EgressRule, error) {
		return EgressRule{}, fmt.Errorf("invalid egress rule %q: %s", s, reason)
	}
	if s == "" {
		return bad("empty")
	}
	if len(s) > 300 {
		return bad("too long")
	}
	if strings.Contains(s, "://") {
		return bad("schemes are not allowed; write the hostname only")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return bad("whitespace is not allowed")
	}

	// [IPv6 CIDR]:port
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return bad("missing ']' after the IPv6 CIDR")
		}
		inner, rest := s[1:end], s[end+1:]
		if !strings.Contains(inner, "/") || !strings.Contains(inner, ":") {
			return bad("brackets must contain an IPv6 CIDR, e.g. [2001:db8::/32]:443")
		}
		if rest == "" {
			return bad("brackets are only needed to add a port; write " + inner + " or [" + inner + "]:443")
		}
		if rest[0] != ':' {
			return bad("expected ':port' after ']'")
		}
		r, err := parsePrefixRule(inner, s)
		if err != nil {
			return EgressRule{}, err
		}
		if r.PortLow, r.PortHigh, err = parsePorts(rest[1:], s); err != nil {
			return EgressRule{}, err
		}
		return r, nil
	}
	if strings.HasSuffix(s, "]") {
		return bad("brackets must open with '['")
	}

	// CIDR[:port]
	if slash := strings.IndexByte(s, '/'); slash >= 0 {
		left, right := s[:slash], s[slash+1:]
		if strings.Contains(left, ":") {
			// IPv6. A ':' after the prefix length cannot be told apart from the address.
			if strings.Contains(right, ":") {
				plen, _, _ := strings.Cut(right, ":")
				return bad("bracket an IPv6 CIDR before adding a port: [" + left + "/" + plen + "]:443")
			}
			return parsePrefixRule(s, s)
		}
		if _, err := netip.ParseAddr(left); err != nil {
			if strings.ContainsAny(left, "*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				return bad("paths and prefix lengths are not allowed on hostnames")
			}
			return bad("not a valid CIDR; write an IPv4 range like 10.0.0.0/8 or 192.0.2.7/32")
		}
		plen, ports, hasPort := strings.Cut(right, ":")
		r, err := parsePrefixRule(left+"/"+plen, s)
		if err != nil {
			return EgressRule{}, err
		}
		if hasPort {
			if r.PortLow, r.PortHigh, err = parsePorts(ports, s); err != nil {
				return EgressRule{}, err
			}
		}
		return r, nil
	}

	// hostname[:port]
	if _, err := netip.ParseAddr(s); err == nil {
		if strings.Contains(s, ":") {
			return bad("an IPv6 address goes in CIDR form, e.g. " + s + "/128, bracketed to add a port: [" + s + "/128]:443")
		}
		return bad("an IP address goes in CIDR form, e.g. " + s + "/32")
	}
	host, ports, hasPort := strings.Cut(s, ":")
	if strings.Contains(ports, ":") {
		return bad("only one ':' is allowed, as host:port; an IPv6 address goes in CIDR form, bracketed to add a port: [2001:db8::1/128]:443")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return bad("an IP address goes in CIDR form, e.g. " + host + "/32")
	}
	r := EgressRule{}
	var err error
	if r.Host, r.Wildcard, err = parseHostPattern(host, s); err != nil {
		return EgressRule{}, err
	}
	if hasPort {
		if r.PortLow, r.PortHigh, err = parsePorts(ports, s); err != nil {
			return EgressRule{}, err
		}
	}
	return r, nil
}

func parsePrefixRule(cidr, entry string) (EgressRule, error) {
	n, err := netip.ParsePrefix(cidr)
	if err != nil {
		return EgressRule{}, fmt.Errorf("invalid egress rule %q: not a valid CIDR", entry)
	}
	if n.Addr().Is4In6() {
		return EgressRule{}, fmt.Errorf("invalid egress rule %q: IPv4-mapped IPv6 prefixes are not allowed; write the IPv4 range", entry)
	}
	if n != n.Masked() {
		return EgressRule{}, fmt.Errorf("invalid egress rule %q: CIDR contains host bits; did you mean %s", entry, n.Masked())
	}
	return EgressRule{Prefix: n}, nil
}

// parsePorts accepts "443" or "8000-8100" (decimal, no leading zeros, 1–65535, low < high).
func parsePorts(spec, entry string) (uint16, uint16, error) {
	bad := func(reason string) (uint16, uint16, error) {
		return 0, 0, fmt.Errorf("invalid egress rule %q: %s", entry, reason)
	}
	if spec == "" {
		return bad("missing port after ':'")
	}
	lo, hi, isRange := strings.Cut(spec, "-")
	l, ok := parsePort(lo)
	if !ok {
		return bad("port must be 1-65535 with no leading zeros")
	}
	if !isRange {
		return l, l, nil
	}
	h, ok := parsePort(hi)
	if !ok {
		return bad("port range must be low-high, each 1-65535 with no leading zeros")
	}
	if l > h {
		return bad("port range is reversed; write " + hi + "-" + lo)
	}
	if l == h {
		return bad("write a single port, " + lo + ", instead of a one-port range")
	}
	return l, h, nil
}

func parsePort(s string) (uint16, bool) {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// parseHostPattern validates "host" or "*.host" and returns the host without the wildcard.
func parseHostPattern(pattern, entry string) (string, bool, error) {
	bad := func(reason string) (string, bool, error) {
		return "", false, fmt.Errorf("invalid egress rule %q: %s", entry, reason)
	}
	host, wildcard := pattern, false
	if strings.HasPrefix(pattern, "*.") {
		host, wildcard = pattern[2:], true
		if host == "" {
			return bad("wildcard needs a hostname after '*.', e.g. *.example.com")
		}
	}
	if strings.Contains(host, "*") {
		return bad("'*' is only allowed as the leading '*.' label")
	}
	if err := checkHostname(host); err != nil {
		return bad(err.Error())
	}
	if strings.IndexByte(host, '.') < 0 {
		return bad("a hostname needs at least two labels, e.g. api.example.com; for a single-label name use its address in CIDR form")
	}
	return host, wildcard, nil
}

var (
	errHostEmpty     = errors.New("empty hostname")
	errHostPath      = errors.New("paths are not allowed")
	errHostLiteral   = errors.New("IP literals are not allowed")
	errHostColon     = errors.New("ports and IPv6 literals are not allowed")
	errHostDot       = errors.New("trailing dot is not allowed")
	errHostCase      = errors.New("must be lowercase")
	errHostNumeric   = errors.New("IP addresses belong in CIDR form (the last label cannot be numeric)")
	errHostLong      = errors.New("hostname longer than 253 characters")
	errHostLabelLen  = errors.New("each label must be 1–63 characters")
	errHostLabelDash = errors.New("a label cannot start or end with '-'")
	errHostChars     = errors.New("only a-z, 0-9, '-' and '.' are allowed")
)

// checkHostname is the shared RFC 1123 check for egress hostnames, egress_allowed_domains
// and Event.DestHost. It returns a bare reason; callers add the quoted subject. It
// allocates nothing on either path so the engine can run it per event.
func checkHostname(host string) error {
	if host == "" {
		return errHostEmpty
	}
	if strings.ContainsAny(host, "/?#") {
		return errHostPath
	}
	if host[0] == '[' || host[len(host)-1] == ']' {
		return errHostLiteral
	}
	if strings.IndexByte(host, ':') >= 0 {
		return errHostColon
	}
	if host[len(host)-1] == '.' {
		return errHostDot
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; c >= 'A' && c <= 'Z' {
			return errHostCase
		}
	}
	if len(host) > 253 {
		return errHostLong
	}
	start := 0
	for i := 0; i <= len(host); i++ {
		if i < len(host) && host[i] != '.' {
			continue
		}
		label := host[start:i]
		start = i + 1
		if len(label) == 0 || len(label) > 63 {
			return errHostLabelLen
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errHostLabelDash
		}
		digits := true
		for j := 0; j < len(label); j++ {
			c := label[j]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errHostChars
			}
			if c < '0' || c > '9' {
				digits = false
			}
		}
		if i == len(host) && digits {
			return errHostNumeric
		}
	}
	return nil
}

// validDestHost accepts what Event.DestHost may carry: a concrete lowercase hostname of
// at least two labels (no wildcard, no IP literal), the same shape a hostname rule has.
// Allocation-free.
func validDestHost(host string) bool {
	return host != "" && strings.IndexByte(host, '*') < 0 && strings.IndexByte(host, '.') >= 0 && checkHostname(host) == nil
}

// EgressHosts returns the hostnames (including "*." wildcards, in profile order, without
// duplicates or ports) named by the profile's egress_allowed rules. The sensor resolves
// these to fill Event.DestHost (CONTRACTS §4); the engine does no DNS itself.
func (p *Profile) EgressHosts() []string {
	if p == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range p.EgressAllow {
		r, err := ParseEgressRule(s)
		if err != nil || !r.IsHost() {
			continue
		}
		name := r.Host
		if r.Wildcard {
			name = "*." + name
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}
