// Package policy evaluates normalized observations. It never executes a response.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Profile extends Rajiv's profile.go schema. Absence of read_allowed preserves
// its read-denylist semantics; an explicit [] denies every non-decoy read.
type Profile struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Description string   `json:"description"`
	Version     int      `json:"version"`
	Mode        Mode     `json:"mode"`
	Decoys      []string `json:"decoys"`
	ProtectRead []string `json:"protected_read"`
	ReadAllow   []string `json:"read_allowed"`
	WriteAllow  []string `json:"write_allowed"`
	ExecAllow   []string `json:"exec_allowed_classes"`
	ExecDeny    []string `json:"exec_denied_classes"`
	// EgressAllow holds up to 128 egress rules in the grammar of ParseEgressRule: a CIDR,
	// a CIDR with a port or port range, a hostname or "*." wildcard with an optional port.
	// Hostname rules match Event.DestHost only (the name the SENSOR resolved); the engine
	// does no DNS. EgressHosts lists the names a sensor must resolve.
	EgressAllow []string `json:"egress_allowed"`
	// EgressAllowDomains is validated and stored but NEVER consulted by Evaluate, which
	// matches egress_allowed only. The controller resolves these
	// names (A/AAAA) when it compiles a profile set and again every refresh, appends the
	// resulting /32 and /128 prefixes to EgressAllow, and rebuilds the engine. A name the
	// engine has not been handed an address for is therefore still out of scope.
	EgressAllowDomains []string       `json:"egress_allowed_domains"`
	Response           ResponsePolicy `json:"response"`
}

// EgressDomains returns a copy of the profile's egress_allowed_domains entries, already
// validated by compile. Each is a lowercase hostname, optionally prefixed with "*.".
// The engine does not match on them; callers resolve them to addresses themselves.
func (p *Profile) EgressDomains() []string {
	if p == nil || p.EgressAllowDomains == nil {
		return nil
	}
	return append([]string{}, p.EgressAllowDomains...)
}

type Mode string

const (
	Shadow Mode = "SHADOW_MODE"
	Active Mode = "ACTIVE_FREEZE_MODE"
)

type Action string

const (
	NoAction Action = "NONE"
	Alert    Action = "ALERT"
	Pause    Action = "PAUSE_CONTAINER"
	Revoke   Action = "REVOKE_SESSION"
)

type ResponsePolicy struct {
	OnViolation       Action `json:"on_violation"`
	OnStructuralGuard Action `json:"on_structural_guard"`
}

// compiledProfile carries the immutable profile plus its precompiled egress matchers.
// egress holds every egress_allowed entry in order; hostRules is true when at least one
// of them matches by hostname, which decides the "host_unknown" finding detail.
type compiledProfile struct {
	profile   Profile
	egress    []EgressRule
	hostRules bool
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var fullContainer = regexp.MustCompile(`^[a-f0-9]{64}$`)
var classes = map[string]bool{"DIAGNOSTIC": true, "INTERPRETER": true, "NET_CLIENT": true, "PRIVILEGED_TOOL": true, "OTHER": true}

// LoadProfiles is atomic: any invalid file rejects the entire directory.
func LoadProfiles(dir string) (map[string]*Profile, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("profile path is not a directory")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) > maxProfiles {
		return nil, fmt.Errorf("too many profiles")
	}
	docs := make([]Document, 0, len(files))
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
		file.Close()
		if err != nil {
			return nil, err
		}
		docs = append(docs, Document{Source: f, Data: data})
	}
	return ParseProfiles(docs)
}

// Document is one profile's JSON and where it came from (a file name, or an API profile name).
type Document struct {
	Source string
	Data   []byte
}

const (
	maxProfiles     = 256
	maxProfileBytes = 256 * 1024
	maxEgressRules  = 128
)

// ParseProfiles applies the same strict checks as LoadProfiles to profiles that did not
// come from files, such as a bundle fetched from the River3 API. It is atomic: any invalid
// document rejects the whole set.
func ParseProfiles(docs []Document) (map[string]*Profile, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("no profiles found")
	}
	if len(docs) > maxProfiles {
		return nil, fmt.Errorf("too many profiles")
	}
	out := map[string]*Profile{}
	for _, doc := range docs {
		if len(doc.Data) > maxProfileBytes {
			return nil, fmt.Errorf("%s: profile too large", doc.Source)
		}
		var p Profile
		if err := DecodeStrict(doc.Data, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", doc.Source, err)
		}
		cp, err := compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", doc.Source, err)
		}
		if _, exists := out[p.Name]; exists {
			return nil, fmt.Errorf("duplicate profile name %q", p.Name)
		}
		copy := cp.profile
		out[p.Name] = &copy
	}
	return out, nil
}

// DecodeStrict rejects duplicate keys, unknown fields and multiple JSON values.
// Callers must impose their own input byte limit before invoking it.
func DecodeStrict(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("expected a single JSON value")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting too deep")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := k.(string)
			if !ok {
				return fmt.Errorf("invalid key")
			}
			fold := strings.ToLower(s)
			if keys[fold] {
				return fmt.Errorf("duplicate JSON key %q", s)
			}
			keys[fold] = true
			if err = uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}
func compile(p Profile) (compiledProfile, error) {
	// Deep copy caller-owned slices before retaining them for concurrent reads.
	clone := func(a []string) []string {
		if a == nil {
			return nil
		}
		return append([]string{}, a...)
	}
	p.Decoys = clone(p.Decoys)
	p.ProtectRead = clone(p.ProtectRead)
	p.ReadAllow = clone(p.ReadAllow)
	p.WriteAllow = clone(p.WriteAllow)
	p.ExecAllow = clone(p.ExecAllow)
	p.ExecDeny = clone(p.ExecDeny)
	p.EgressAllow = clone(p.EgressAllow)
	p.EgressAllowDomains = clone(p.EgressAllowDomains)
	cp := compiledProfile{profile: p}
	bad := func(s string) (compiledProfile, error) {
		return compiledProfile{}, fmt.Errorf("profile %q: %s", p.Name, s)
	}
	if !identifier.MatchString(p.Name) {
		return bad("invalid name")
	}
	if p.Kind != "ai_worker" && p.Kind != "shared_service" {
		return bad("kind must be ai_worker or shared_service")
	}
	if len(p.Description) > 2048 {
		return bad("description too long")
	}
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Version < 1 {
		return bad("invalid version")
	}
	if p.Mode == "" {
		p.Mode = Shadow
	}
	if p.Mode != Shadow && p.Mode != Active {
		return bad("invalid mode")
	}
	if p.Response.OnViolation == "" {
		p.Response.OnViolation = Alert
	}
	if p.Response.OnStructuralGuard == "" {
		p.Response.OnStructuralGuard = Alert
	}
	for _, a := range []Action{p.Response.OnViolation, p.Response.OnStructuralGuard} {
		if a != Alert && a != Pause && a != Revoke {
			return bad("response must be ALERT, PAUSE_CONTAINER or REVOKE_SESSION")
		}
		if p.Kind == "shared_service" && a == Pause {
			return bad("shared services cannot use container pause")
		}
	}
	// on_structural_guard is the one place a verified Channel A model verdict can lead to an action.
	// Keep that ceiling at a container pause (reversible, scoped to a dedicated AI worker): revoking
	// a session is a stronger, cross-system action that only a deterministic violation may trigger.
	if p.Response.OnStructuralGuard == Revoke {
		return bad("on_structural_guard: a model verdict may at most pause a dedicated AI worker; session revocation needs a deterministic violation")
	}
	for _, list := range [][]string{p.Decoys, p.ProtectRead, p.ReadAllow, p.WriteAllow} {
		if len(list) > 128 {
			return bad("too many path patterns")
		}
		for _, pat := range list {
			if err := validatePattern(pat); err != nil {
				return bad(err.Error())
			}
		}
	}
	for _, list := range [][]string{p.ExecAllow, p.ExecDeny} {
		if len(list) > len(classes) {
			return bad("too many execution classes")
		}
		for _, s := range list {
			if !classes[s] {
				return bad("unknown execution class " + s)
			}
		}
	}
	if len(p.EgressAllow) > maxEgressRules {
		return bad("too many egress_allowed entries (max 128)")
	}
	if len(p.EgressAllow) > 0 {
		cp.egress = make([]EgressRule, 0, len(p.EgressAllow))
	}
	for _, s := range p.EgressAllow {
		r, err := ParseEgressRule(s)
		if err != nil {
			return bad(err.Error())
		}
		if r.IsHost() {
			cp.hostRules = true
		}
		cp.egress = append(cp.egress, r)
	}
	if len(p.EgressAllowDomains) > 128 {
		return bad("too many egress domains")
	}
	for _, s := range p.EgressAllowDomains {
		if err := validateDomain(s); err != nil {
			return bad(err.Error())
		}
	}
	cp.profile = p
	return cp, nil
}

// validateDomain accepts a lowercase DNS hostname, optionally prefixed with "*." for a
// wildcard. Labels are 1–63 characters of [a-z0-9-], not starting or ending with '-';
// the hostname is at most 253 characters. IP literals, ports, schemes, paths, trailing
// dots and uppercase are rejected rather than normalized: the console and the API send
// the exact string the controller will resolve.
func validateDomain(s string) error {
	quoted := fmt.Sprintf("invalid egress domain %q", s)
	if s == "" {
		return fmt.Errorf("%s: empty", quoted)
	}
	if len(s) > 255 {
		return fmt.Errorf("%s: too long", quoted)
	}
	if strings.Contains(s, "://") {
		return fmt.Errorf("%s: schemes are not allowed", quoted)
	}
	if strings.ContainsAny(s, "/?#") {
		return fmt.Errorf("%s: paths are not allowed", quoted)
	}
	if strings.Contains(s, ":") {
		return fmt.Errorf("%s: ports and IPv6 literals are not allowed", quoted)
	}
	host := strings.TrimPrefix(s, "*.")
	if host == "" || strings.Contains(host, "*") {
		return fmt.Errorf("%s: wildcard is only allowed as a leading \"*.\"", quoted)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Errorf("%s: IP addresses belong in egress_allowed", quoted)
	}
	if err := checkHostname(host); err != nil {
		return fmt.Errorf("%s: %v", quoted, err)
	}
	return nil
}
func canonicalPath(s string) bool {
	if len(s) == 0 || len(s) > 4096 || !utf8.ValidString(s) || !strings.HasPrefix(s, "/") || strings.Contains(s, "\\") || strings.HasSuffix(s, " (deleted)") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return path.Clean(s) == s
}
func validatePattern(s string) error {
	if !canonicalPath(s) {
		return fmt.Errorf("non-canonical absolute path pattern %q", s)
	}
	base := s
	if strings.HasSuffix(s, "/**") {
		base = strings.TrimSuffix(s, "/**")
		if base != "" && strings.ContainsAny(base, "*?[\\") {
			return fmt.Errorf("subtree prefix must be literal: %q", s)
		}
	}
	if strings.Contains(base, "**") {
		return fmt.Errorf("** is supported only as a final subtree suffix")
	}
	if _, err := path.Match(base, "/"); err != nil {
		return fmt.Errorf("bad glob %q", s)
	}
	return nil
}
func globMatch(pattern, resource string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return prefix == "" || resource == prefix || strings.HasPrefix(resource, prefix+"/")
	}
	ok, _ := path.Match(pattern, resource)
	return ok
}
func anyMatch(patterns []string, resource string) (string, bool) {
	for _, p := range patterns {
		if globMatch(p, resource) {
			return p, true
		}
	}
	return "", false
}
func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
