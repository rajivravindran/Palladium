package adapter

import (
	"context"
	"errors"

	policy "river3.local/policy"
)

// SessionState is a gateway's view of one agent session (CONTRACTS.md §2.1).
type SessionState string

const (
	SessionActive  SessionState = "active"
	SessionRevoked SessionState = "revoked"
	SessionEnded   SessionState = "ended"
	SessionUnknown SessionState = "unknown" // the gateway does not know the id (404) or said so
)

// SessionInfo is the inspected state of a session: the reply to GET /v1/sessions/{id}.
//
// Everything in it is a gateway claim (Channel B, CONTRACTS.md §0). It decides only
// whether a revoke is VERIFIED, FAILED or UNKNOWN, and which principal is named in
// the journal; it never decides whether a violation happened, which is Channel A's.
type SessionInfo struct {
	ID        string       `json:"id"`
	State     SessionState `json:"state"`
	Principal string       `json:"principal,omitempty"`
	StartedAt string       `json:"started_at,omitempty"`
}

// ErrSessionUnknown is returned by Revoke when the gateway answers 404: there is no
// such session to revoke. (InspectSession maps a 404 to SessionUnknown instead, since
// "unknown" is a legitimate inspected state the controller journals as UNKNOWN.)
var ErrSessionUnknown = errors.New("session adapter: gateway does not know this session")

// SessionAdapter is the only way the controller revokes a session. It is separate from
// Adapter because the two act on different things through different parties: Adapter
// pauses a container through the node's runtime; SessionAdapter asks the customer's
// gateway to cut off one agent run. A node may have either, both or neither.
type SessionAdapter interface {
	// Name is reported in incidents and the audit trail (e.g. "gateway").
	Name() string
	// Actions feeds Context.AdapterActions alongside the runtime adapter's; it
	// advertises REVOKE_SESSION, which clears the engine's ADAPTER_UNAVAILABLE blocker.
	Actions() []policy.Action
	// Revoke asks the gateway to end the session. The returned state is what the
	// gateway claimed in its reply; the controller inspects afterwards regardless.
	Revoke(ctx context.Context, sessionID, reason, incidentID, idempotencyKey string) (SessionState, error)
	// InspectSession returns the gateway's current state for the session. A session
	// the gateway does not know is SessionUnknown with a nil error.
	InspectSession(ctx context.Context, sessionID string) (SessionInfo, error)
}
