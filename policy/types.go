package policy

import "time"

type Operation string

const (
	FileOpen    Operation = "FILE_OPEN"
	ProcessExec Operation = "PROCESS_EXEC"
	NetConnect  Operation = "NET_CONNECT"
)

type Outcome string

const (
	Succeeded      Outcome = "SUCCEEDED"
	Attempted      Outcome = "ATTEMPTED"
	Failed         Outcome = "FAILED"
	UnknownOutcome Outcome = "UNKNOWN"
)

type Provenance string

const (
	Live       Provenance = "LIVE"
	Historical Provenance = "HISTORICAL"
	Simulation Provenance = "SIMULATION"
)

// Identity must come from enrollment and authenticated event correlation.
// Labels, short container IDs, PIDs or source IPs alone cannot establish it.
type Identity struct {
	TenantID    string `json:"tenant_id"`
	AssetID     string `json:"asset_id"`
	HostID      string `json:"host_id"`
	Generation  string `json:"generation"`
	ContainerID string `json:"container_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
}

// Event is normalized sensor evidence, not arbitrary raw Falco JSON.
// An open success is not proof of a read or transmission.
type Event struct {
	ID            string     `json:"id"`
	Identity      Identity   `json:"identity"`
	ObservedAt    time.Time  `json:"observed_at"`
	Provenance    Provenance `json:"provenance"`
	Operation     Operation  `json:"operation"`
	Outcome       Outcome    `json:"outcome"`
	Path          string     `json:"path,omitempty"`
	OpenRead      bool       `json:"open_read,omitempty"`
	OpenWrite     bool       `json:"open_write,omitempty"`
	BinaryClass   string     `json:"binary_class,omitempty"`
	DestinationIP string     `json:"destination_ip,omitempty"`
	// Port is the destination port of a NET_CONNECT; 0 means the sensor did not report it.
	// A rule that names a port never matches an event whose port is unknown.
	Port uint16 `json:"port,omitempty"`
	// DestHost is the lowercase hostname the SENSOR resolved for DestinationIP (from its own
	// forward-resolution cache of the profile's names), or "" when unknown. It is the only
	// thing hostname rules match against; the engine performs no DNS. When set it must be a
	// valid RFC 1123 hostname or the event is rejected.
	DestHost string `json:"dest_host,omitempty"`
}

type GuardVerdict string

const (
	Continue    GuardVerdict = "CONTINUE"
	Warn        GuardVerdict = "WARN_OPERATOR"
	Contain     GuardVerdict = "REQUEST_CONTAINMENT"
	Unavailable GuardVerdict = "UNAVAILABLE"
)

type Assessment struct {
	EventID  string
	Identity Identity
	Channel  string // A or B; separate upstream model calls are required.
	Verdict  GuardVerdict
	Verified bool // Set by trusted model adapter, never by model output.
}

// Context is exclusively controller-owned. JSON decoding cannot populate it.
// These flags are integration prerequisites, NOT authentication implemented here.
type Context struct {
	ProfileName         string       `json:"-"`
	ProfileVersion      int          `json:"-"`
	Identity            Identity     `json:"-"`
	Now                 time.Time    `json:"-"`
	IdentityVerified    bool         `json:"-"`
	SensorAuthenticated bool         `json:"-"`
	ResourceVerified    bool         `json:"-"` // namespace/file identity, executable class or socket destination
	Healthy             bool         `json:"-"`
	Active              bool         `json:"-"`
	DedicatedContainer  bool         `json:"-"`
	PermittedActions    []Action     `json:"-"`
	AdapterActions      []Action     `json:"-"`
	Assessments         []Assessment `json:"-"`
}

type Status string

const (
	InScope   Status = "IN_SCOPE"
	Violation Status = "VIOLATION"
	Review    Status = "REVIEW"
	Unknown   Status = "UNKNOWN"
)

type Finding struct {
	Code string `json:"code"`
	Rule string `json:"rule,omitempty"`
}
type Candidate struct {
	Action         Action    `json:"action"`
	Target         Identity  `json:"target"`
	PolicyName     string    `json:"policy_name"`
	PolicyVersion  int       `json:"policy_version"`
	EvidenceID     string    `json:"evidence_id"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	IdempotencyKey string    `json:"idempotency_key"`
}
type Decision struct {
	EventID           string     `json:"event_id"`
	Outcome           Outcome    `json:"observed_outcome"`
	Provenance        Provenance `json:"provenance"`
	ProfileName       string     `json:"profile_name"`
	ProfileVersion    int        `json:"profile_version"`
	Mode              Mode       `json:"mode"`
	Status            Status     `json:"status"`
	Findings          []Finding  `json:"findings"`
	RecommendedAction Action     `json:"recommended_action"`
	Action            Action     `json:"action"` // eligible candidate, never a completed response
	Blockers          []string   `json:"blockers"`
	Candidate         *Candidate `json:"candidate,omitempty"`
}

type Options struct {
	MaxEventAge   time.Duration
	MaxFutureSkew time.Duration
	ActionTTL     time.Duration
}
