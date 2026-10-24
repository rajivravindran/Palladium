package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// Engine is immutable after construction and safe for concurrent evaluations.
// It has no sockets, subprocesses, model API calls or mutable incident state.
type Engine struct {
	profiles map[string]compiledProfile
	options  Options
}

func NewEngine(profiles []Profile, options Options) (*Engine, error) {
	if len(profiles) == 0 || len(profiles) > 256 {
		return nil, fmt.Errorf("require 1..256 profiles")
	}
	if options.MaxEventAge == 0 {
		options.MaxEventAge = 30 * time.Second
	}
	if options.MaxFutureSkew == 0 {
		options.MaxFutureSkew = 2 * time.Second
	}
	if options.ActionTTL == 0 {
		options.ActionTTL = 5 * time.Second
	}
	if options.MaxEventAge < 0 || options.MaxEventAge > 5*time.Minute || options.MaxFutureSkew < 0 || options.MaxFutureSkew > 10*time.Second || options.ActionTTL < 0 || options.ActionTTL > 30*time.Second {
		return nil, fmt.Errorf("invalid freshness/expiry bounds")
	}
	e := &Engine{profiles: make(map[string]compiledProfile), options: options}
	for _, p := range profiles {
		cp, err := compile(p)
		if err != nil {
			return nil, err
		}
		if _, exists := e.profiles[p.Name]; exists {
			return nil, fmt.Errorf("duplicate profile %q", p.Name)
		}
		e.profiles[p.Name] = cp
	}
	return e, nil
}

func validateIdentity(id Identity) bool {
	for _, s := range []string{id.TenantID, id.AssetID, id.HostID, id.Generation} {
		if !identifier.MatchString(s) {
			return false
		}
	}
	return (id.ContainerID == "" || fullContainer.MatchString(id.ContainerID)) && (id.SessionID == "" || identifier.MatchString(id.SessionID))
}
func validateEvent(v Event) error {
	if !identifier.MatchString(v.ID) || !validateIdentity(v.Identity) || v.ObservedAt.IsZero() {
		return fmt.Errorf("invalid event identity or timestamp")
	}
	if v.Provenance != Live && v.Provenance != Historical && v.Provenance != Simulation {
		return fmt.Errorf("invalid provenance")
	}
	if v.Outcome != Succeeded && v.Outcome != Failed && v.Outcome != Attempted && v.Outcome != UnknownOutcome {
		return fmt.Errorf("invalid outcome")
	}
	switch v.Operation {
	case FileOpen:
		if v.BinaryClass != "" || v.DestinationIP != "" || v.Port != 0 || v.DestHost != "" {
			return fmt.Errorf("mixed operation fields")
		}
	case ProcessExec:
		if v.Path != "" || v.DestinationIP != "" || v.Port != 0 || v.DestHost != "" || v.OpenRead || v.OpenWrite {
			return fmt.Errorf("mixed operation fields")
		}
	case NetConnect:
		if v.Path != "" || v.BinaryClass != "" || v.OpenRead || v.OpenWrite {
			return fmt.Errorf("mixed operation fields")
		}
		if v.DestHost != "" && !validDestHost(v.DestHost) {
			return fmt.Errorf("invalid destination host %q", v.DestHost)
		}
	default:
		return fmt.Errorf("unsupported operation %q", v.Operation)
	}
	return nil
}

func (e *Engine) Evaluate(v Event, ctx Context) (Decision, error) {
	if e == nil {
		return Decision{}, fmt.Errorf("nil engine")
	}
	if err := validateEvent(v); err != nil {
		return Decision{}, err
	}
	cp, ok := e.profiles[ctx.ProfileName]
	if !ok {
		return Decision{}, fmt.Errorf("unknown profile %q", ctx.ProfileName)
	}
	p := cp.profile
	d := Decision{EventID: v.ID, Outcome: v.Outcome, Provenance: v.Provenance, ProfileName: p.Name, ProfileVersion: p.Version, Mode: p.Mode, Status: InScope, Findings: []Finding{}, RecommendedAction: NoAction, Action: NoAction, Blockers: []string{}}
	finding := func(code, rule string) { d.Findings = append(d.Findings, Finding{code, rule}); d.Status = Violation }
	unknown := func(code string) {
		d.Findings = append(d.Findings, Finding{Code: code})
		if d.Status != Violation {
			d.Status = Unknown
		}
	}
	switch v.Operation {
	case FileOpen:
		if !canonicalPath(v.Path) || (!v.OpenRead && !v.OpenWrite) {
			unknown("UNRESOLVED_FILE_OPEN")
			break
		}
		if pat, ok := anyMatch(p.Decoys, v.Path); ok {
			finding("DECOY_OPEN", pat)
		}
		if v.OpenRead {
			if pat, ok := anyMatch(p.ProtectRead, v.Path); ok {
				finding("PROTECTED_OPEN", pat)
			} else if p.ReadAllow != nil {
				if _, ok := anyMatch(p.ReadAllow, v.Path); !ok {
					finding("READ_OUTSIDE_SCOPE", "")
				}
			}
		}
		if v.OpenWrite {
			if _, ok := anyMatch(p.WriteAllow, v.Path); !ok {
				finding("WRITE_OUTSIDE_SCOPE", "")
			}
		}
	case ProcessExec:
		if !classes[v.BinaryClass] {
			unknown("UNKNOWN_EXEC_CLASS")
			break
		}
		if contains(p.ExecDeny, v.BinaryClass) {
			finding("EXEC_CLASS_DENIED", v.BinaryClass)
		} else if !contains(p.ExecAllow, v.BinaryClass) {
			finding("EXEC_CLASS_NOT_ALLOWED", v.BinaryClass)
		}
	case NetConnect:
		// There is no DNS in the engine. CIDR rules match the destination address; a
		// hostname rule matches only the name the sensor already resolved into DestHost;
		// a rule with a port needs a known, in-range Port. egress_allowed_domains is still
		// not consulted here: the controller resolves those into egress_allowed prefixes.
		addr, err := netip.ParseAddr(v.DestinationIP)
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
			unknown("UNRESOLVED_DESTINATION")
			break
		}
		addr = addr.Unmap()
		allowed := false
		for i := range cp.egress {
			if cp.egress[i].matches(addr, v.Port, v.DestHost) {
				allowed = true
				break
			}
		}
		if !allowed {
			finding("EGRESS_OUTSIDE_SCOPE", egressDetail(cp, addr, v))
		}
	}
	deterministic := d.Status == Violation
	if deterministic {
		d.RecommendedAction = p.Response.OnViolation
	}
	if d.Status == Unknown {
		d.RecommendedAction = Alert
	}

	// Model assessments are evidence-bound recommendations, never execution text.
	if len(ctx.Assessments) > 2 {
		unknown("INVALID_GUARD_ASSESSMENTS")
	} else {
		seen := map[string]bool{}
		duplicate := false
		for _, a := range ctx.Assessments {
			if seen[a.Channel] {
				duplicate = true
			}
			seen[a.Channel] = true
		}
		if duplicate {
			unknown("DUPLICATE_GUARD_CHANNEL")
		} else {
			for _, a := range ctx.Assessments {
				if !a.Verified || a.EventID != v.ID || a.Identity != v.Identity || (a.Channel != "A" && a.Channel != "B") || (a.Verdict != Continue && a.Verdict != Warn && a.Verdict != Contain && a.Verdict != Unavailable) {
					unknown("UNTRUSTED_GUARD_ASSESSMENT")
					continue
				}
				if a.Verdict == Continue {
					continue
				}
				if a.Verdict == Unavailable {
					unknown("GUARD_UNAVAILABLE")
					continue
				}
				d.Findings = append(d.Findings, Finding{Code: "GUARD_" + a.Channel + "_" + string(a.Verdict)})
				if d.Status == InScope {
					d.Status = Review
				}
				if d.RecommendedAction == NoAction {
					d.RecommendedAction = Alert
				}
				if !deterministic && a.Channel == "A" && a.Verdict == Contain {
					// compile() guarantees OnStructuralGuard is ALERT or PAUSE_CONTAINER; the engine
					// clamps here as well so a model verdict can never recommend REVOKE_SESSION even
					// if a profile reaches the engine by another path (falls back to ALERT, never up).
					if p.Response.OnStructuralGuard == Revoke {
						d.RecommendedAction = Alert
					} else {
						d.RecommendedAction = p.Response.OnStructuralGuard
					}
				}
				// Payload-only findings alert. They cannot cancel structural findings.
			}
		}
	}
	if d.Status == Unknown && d.RecommendedAction == NoAction {
		d.RecommendedAction = Alert
	}
	blocker := func(s string) { d.Blockers = append(d.Blockers, s) }
	if !validateIdentity(ctx.Identity) || !ctx.IdentityVerified || ctx.Identity != v.Identity {
		blocker("IDENTITY_NOT_VERIFIED")
	}
	if ctx.ProfileVersion != p.Version {
		blocker("POLICY_VERSION_MISMATCH")
	}
	if !ctx.SensorAuthenticated {
		blocker("UNAUTHENTICATED_SENSOR")
	}
	if !ctx.Healthy || !ctx.Active {
		blocker("WORKLOAD_NOT_READY")
	}
	if !ctx.ResourceVerified {
		blocker("RESOURCE_NOT_VERIFIED")
	}
	if ctx.Now.IsZero() {
		blocker("MISSING_CONTROLLER_TIME")
	} else {
		age := ctx.Now.Sub(v.ObservedAt)
		if age > e.options.MaxEventAge {
			blocker("STALE_EVENT")
		}
		if age < -e.options.MaxFutureSkew {
			blocker("FUTURE_EVENT")
		}
	}
	// These blockers are visible even when the lexical rules appear benign.
	if len(d.Blockers) > 0 && d.Status == InScope {
		d.Status = Unknown
		d.RecommendedAction = Alert
	}
	if d.RecommendedAction != Pause && d.RecommendedAction != Revoke {
		d.Action = d.RecommendedAction
		return d, nil
	}
	if p.Mode != Active {
		blocker("SHADOW_MODE")
	}
	if v.Provenance != Live {
		blocker("NON_LIVE_EVIDENCE")
	}
	if v.Outcome != Succeeded {
		blocker("OUTCOME_NOT_SUCCESSFUL")
	}
	if d.Status == Unknown {
		blocker("INCOMPLETE_ASSESSMENT")
	}
	if !contains(ctx.PermittedActions, d.RecommendedAction) {
		blocker("ACTION_NOT_PERMITTED")
	}
	if !contains(ctx.AdapterActions, d.RecommendedAction) {
		blocker("ADAPTER_UNAVAILABLE")
	}
	if d.RecommendedAction == Pause && (p.Kind != "ai_worker" || !ctx.DedicatedContainer || !fullContainer.MatchString(ctx.Identity.ContainerID)) {
		blocker("NOT_A_DEDICATED_BOUND_CONTAINER")
	}
	if d.RecommendedAction == Revoke && ctx.Identity.SessionID == "" {
		blocker("NO_BOUND_SESSION")
	}
	if len(d.Blockers) > 0 {
		d.Action = Alert
		return d, nil
	}
	d.Action = d.RecommendedAction
	key, err := candidateKey(p, v, d.Action)
	if err != nil {
		return Decision{}, err
	}
	d.Candidate = &Candidate{Action: d.Action, Target: ctx.Identity, PolicyName: p.Name, PolicyVersion: p.Version, EvidenceID: v.ID, IssuedAt: ctx.Now, ExpiresAt: ctx.Now.Add(e.options.ActionTTL), IdempotencyKey: key}
	return d, nil
}

// egressDetail is the Finding.Rule for EGRESS_OUTSIDE_SCOPE: "host_unknown" when the
// profile has hostname rules but the sensor supplied no DestHost (the connection may well
// have been to an allowed name; the operator should check sensor resolution), otherwise
// the destination as ip:port ("[v6]:port" for IPv6), or just the address when the port
// is unknown. Only reached on the violation path, which allocates for the finding anyway.
func egressDetail(cp compiledProfile, addr netip.Addr, v Event) string {
	if cp.hostRules && v.DestHost == "" {
		return "host_unknown"
	}
	if v.Port == 0 {
		return addr.String()
	}
	return netip.AddrPortFrom(addr, v.Port).String()
}

func candidateKey(p Profile, v Event, action Action) (string, error) {
	b, err := json.Marshal(struct {
		Profile Profile
		Event   Event
		Action  Action
	}{p, v, action})
	if err != nil {
		return "", fmt.Errorf("cannot encode action identity: %w", err)
	}
	sum := sha256.Sum256(b)
	return "policy_" + hex.EncodeToString(sum[:]), nil
}

// Revalidate is required immediately before handing a candidate to an adapter.
// The controller must authenticate the caller and refresh Context from its own
// registry; persist idempotency atomically and verify actual post-action state.
func (e *Engine) Revalidate(c Candidate, v Event, current Context) error {
	if e == nil {
		return fmt.Errorf("nil engine")
	}
	if current.Now.IsZero() || c.IssuedAt.After(current.Now) || !c.ExpiresAt.After(current.Now) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > e.options.ActionTTL {
		return fmt.Errorf("candidate is expired or has an invalid lease")
	}
	d, err := e.Evaluate(v, current)
	if err != nil {
		return err
	}
	n := d.Candidate
	if n == nil || c.Action != n.Action || c.Target != n.Target || c.PolicyName != n.PolicyName || c.PolicyVersion != n.PolicyVersion || c.EvidenceID != n.EvidenceID || c.IdempotencyKey != n.IdempotencyKey {
		return fmt.Errorf("candidate no longer matches current policy, evidence, identity or permissions")
	}
	return nil
}
