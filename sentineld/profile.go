package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// A Profile is the "scope" of a workload: what it is allowed to touch.
// The same engine serves both threats:
//   - ai_worker      : an internal AI agent's task scope   (drift / rogue agent)
//   - shared_service : a business service's normal scope   (external attacker exploits it)
type Profile struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // ai_worker | shared_service
	Description string   `json:"description"`
	Decoys      []string `json:"decoys"`         // canary files: zero legitimate use
	ProtectRead []string `json:"protected_read"` // sensitive paths outside scope
	WriteAllow  []string `json:"write_allowed"`  // where writes are in scope
	ExecAllow   []string `json:"exec_allowed_classes"`
	ExecDeny    []string `json:"exec_denied_classes"`
	EgressAllow []string `json:"egress_allowed"` // CIDRs; empty = no outbound allowed
	egressNets  []*net.IPNet
}

func loadProfiles(dir string) (map[string]*Profile, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]*Profile{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		p := &Profile{}
		if err := json.Unmarshal(b, p); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, c := range p.EgressAllow {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("%s: bad CIDR %q", f, c)
			}
			p.egressNets = append(p.egressNets, n)
		}
		out[p.Name] = p
	}
	return out, nil
}

// globMatch supports "*" within a segment and a trailing "/**" for subtrees.
func globMatch(pattern, p string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return p == prefix || strings.HasPrefix(p, prefix+"/")
	}
	ok, _ := path.Match(pattern, p)
	return ok
}

func anyMatch(patterns []string, p string) (string, bool) {
	for _, pat := range patterns {
		if globMatch(pat, p) {
			return pat, true
		}
	}
	return "", false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
