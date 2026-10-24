package report

import (
	"sort"
	"strings"
	"time"

	policy "river3.local/policy"
)

// Wire types for the River3 API (see api/river3_api/schemas.py).

type EventIn struct {
	ID         string         `json:"id"`
	WorkloadID string         `json:"workload_id"`
	Kind       string         `json:"kind"`
	Outcome    string         `json:"outcome"`
	TS         time.Time      `json:"ts"`
	Facts      map[string]any `json:"facts"`
	Payload    map[string]any `json:"payload"`
}

type DecisionIn struct {
	ProfileName       string            `json:"profile_name"`
	ProfileVersion    int               `json:"profile_version"`
	Status            policy.Status     `json:"status"`
	Findings          []policy.Finding  `json:"findings"`
	RecommendedAction policy.Action     `json:"recommended_action"`
	Action            policy.Action     `json:"action"`
	Blockers          []string          `json:"blockers"`
	Candidate         *policy.Candidate `json:"candidate"`
}

type IncidentIn struct {
	WorkloadID string         `json:"workload_id"`
	Title      string         `json:"title"`
	Threat     string         `json:"threat"`
	Severity   string         `json:"severity"`
	Verdict    string         `json:"verdict"`
	Rule       string         `json:"rule"`
	Reason     string         `json:"reason"`
	Mode       string         `json:"mode"`
	Response   map[string]any `json:"response"`
	Policy     DecisionIn     `json:"policy"`
	Events     []EventIn      `json:"events"`
	Demo       bool           `json:"demo"`
}

var titles = map[string]string{
	"DECOY_OPEN":             "Decoy file opened",
	"PROTECTED_OPEN":         "Protected file opened",
	"READ_OUTSIDE_SCOPE":     "File read outside scope",
	"WRITE_OUTSIDE_SCOPE":    "File write outside scope",
	"EXEC_CLASS_DENIED":      "Denied type of program started",
	"EXEC_CLASS_NOT_ALLOWED": "Program type not in scope started",
	"EGRESS_OUTSIDE_SCOPE":   "Network connection outside scope",
	"UNRESOLVED_FILE_OPEN":   "File access could not be resolved",
	"UNKNOWN_EXEC_CLASS":     "Program type could not be classified",
	"UNRESOLVED_DESTINATION": "Network destination could not be resolved",
}

// Lower number = more important, used to pick the incident's headline finding.
var priority = map[string]int{
	"DECOY_OPEN": 0, "PROTECTED_OPEN": 1, "EXEC_CLASS_DENIED": 2, "EGRESS_OUTSIDE_SCOPE": 3,
	"WRITE_OUTSIDE_SCOPE": 4, "EXEC_CLASS_NOT_ALLOWED": 5, "READ_OUTSIDE_SCOPE": 6,
}

func rank(code string) int {
	if p, ok := priority[code]; ok {
		return p
	}
	if strings.HasPrefix(code, "GUARD_") {
		return 20
	}
	return 50
}

func title(code string) string {
	if t, ok := titles[code]; ok {
		return t
	}
	if strings.HasPrefix(code, "GUARD_") {
		return "Model guard flagged this activity"
	}
	if code == "" {
		return "Activity needs review"
	}
	return strings.ReplaceAll(strings.ToLower(code), "_", " ")
}

func lowerOperation(op policy.Operation) string {
	switch op {
	case policy.FileOpen:
		return "file_open"
	case policy.ProcessExec:
		return "process_exec"
	case policy.NetConnect:
		return "net_connect"
	}
	return strings.ToLower(string(op))
}

func apiOutcome(o policy.Outcome) string {
	switch o {
	case policy.Succeeded:
		return "success"
	case policy.Failed:
		return "failed"
	case policy.Attempted:
		return "pending"
	}
	return "unknown"
}

func access(ev policy.Event) string {
	switch {
	case ev.OpenRead && ev.OpenWrite:
		return "rw"
	case ev.OpenWrite:
		return "write"
	case ev.OpenRead:
		return "read"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// BuildIncident maps an engine decision to the API's incident shape. Pure function.
func BuildIncident(ev policy.Event, d policy.Decision, profileKind string) IncidentIn {
	findings := append([]policy.Finding{}, d.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return rank(findings[i].Code) < rank(findings[j].Code) })

	head := policy.Finding{}
	if len(findings) > 0 {
		head = findings[0]
	}
	severity := "info"
	if d.Status == policy.Violation {
		severity = "high"
	}
	for _, f := range findings {
		if f.Code == "DECOY_OPEN" {
			severity = "critical" // decoys have no legitimate use
		}
	}
	verdict := "unresolved"
	if d.Status == policy.Violation {
		verdict = "prohibited"
	}
	threat := "unknown"
	switch profileKind {
	case "ai_worker":
		threat = "agent_drift"
	case "shared_service":
		threat = "external_exploit"
	}
	mode := "shadow"
	if d.Mode == policy.Active {
		mode = "active"
	}

	codes := make([]string, 0, len(findings))
	for _, f := range findings {
		codes = append(codes, f.Code)
	}
	reason := "Findings: " + strings.Join(codes, ", ") + "."
	if len(codes) == 0 {
		reason = "No rule findings."
	}
	if d.RecommendedAction != policy.NoAction && d.RecommendedAction != d.Action {
		reason += " Recommended " + string(d.RecommendedAction) + ", held at " + string(d.Action) +
			" by: " + strings.Join(d.Blockers, ", ") + "."
	}
	rule := head.Code
	if rule == "" {
		rule = string(d.Status)
	}

	target := map[string]any{}
	if ev.Path != "" {
		target["path"] = ev.Path
		if a := access(ev); a != "" {
			target["access"] = a
		}
	}
	if ev.BinaryClass != "" {
		target["binary_class"] = ev.BinaryClass
	}
	if ev.DestinationIP != "" {
		target["ip"] = ev.DestinationIP
	}
	facts := map[string]any{
		"sensor":     "policy-engine",
		"operation":  string(ev.Operation),
		"outcome":    string(ev.Outcome),
		"provenance": string(ev.Provenance),
		"identity":   ev.Identity,
		"target":     target,
	}

	blockers := d.Blockers
	if blockers == nil {
		blockers = []string{}
	}
	return IncidentIn{
		WorkloadID: ev.Identity.AssetID,
		Title:      truncate(title(head.Code), 512),
		Threat:     threat,
		Severity:   severity,
		Verdict:    verdict,
		Rule:       truncate(rule, 256),
		Reason:     truncate(reason, 2000),
		Mode:       mode,
		Response:   map[string]any{},
		Policy: DecisionIn{
			ProfileName: d.ProfileName, ProfileVersion: d.ProfileVersion, Status: d.Status,
			Findings: findings, RecommendedAction: d.RecommendedAction, Action: d.Action,
			Blockers: blockers, Candidate: d.Candidate,
		},
		Events: []EventIn{{
			ID: ev.ID, WorkloadID: ev.Identity.AssetID, Kind: lowerOperation(ev.Operation),
			Outcome: apiOutcome(ev.Outcome), TS: ev.ObservedAt.UTC(), Facts: facts, Payload: map[string]any{},
		}},
		// Anything that isn't live evidence is flagged so the console marks it.
		Demo: ev.Provenance != policy.Live,
	}
}
