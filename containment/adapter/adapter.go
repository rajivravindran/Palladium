// Package adapter defines the narrow runtime interface the controller may call.
//
// Every call takes structured arguments; nothing here becomes a shell command.
// An adapter error is never containment success: the controller always inspects
// the real runtime state afterwards and records that, not the call's return value.
package adapter

import (
	"context"
	"errors"

	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// Status is the runtime's own view of a container.
type Status string

const (
	Running Status = "running"
	Paused  Status = "paused"
	Exited  Status = "exited"  // stopped or removed
	Missing Status = "missing" // the runtime has no container with this id
	Unknown Status = "unknown" // anything else the runtime reported
)

// Info is the inspected state. ContainerID is the full id the runtime reports;
// Generation is the runtime's restart marker (mock: a fixed string; podman and
// docker: State.StartedAt). Note is set when something about the answer is weaker
// than it looks (openshell: the generation is echoed from configuration, not
// observed) and is copied into the journaled evidence.
type Info struct {
	ContainerID string `json:"container_id"`
	Generation  string `json:"generation"`
	Status      Status `json:"status"`
	Note        string `json:"note,omitempty"`
}

var ErrUnsupported = errors.New("adapter: action not supported")

// Lister is implemented by adapters whose runtime can enumerate the containers
// that opted into River3 with labels (CONTRACTS.md §4.1). It is separate from
// Adapter because not every adapter has a runtime to list (mock, openshell), and
// because discovery may run against a different runtime than the one the adapter
// acts on (`-runtime`).
type Lister interface {
	// ListEnrolled returns every running container carrying river3.enroll=true,
	// with the generation the adapter's Inspect would report for it right now.
	ListEnrolled(ctx context.Context) ([]registry.Container, error)
}

// Adapter is the only way the controller touches a runtime.
type Adapter interface {
	// Name is reported in incidents and the audit trail (e.g. "mock", "podman").
	Name() string
	// Actions lists the automatic actions this adapter can perform. It feeds
	// Context.AdapterActions, so the engine blocks anything not listed.
	Actions() []policy.Action
	// Inspect returns the real current state. It must never guess.
	Inspect(ctx context.Context, containerID string) (Info, error)
	Pause(ctx context.Context, containerID string) error
	Resume(ctx context.Context, containerID string) error
	Terminate(ctx context.Context, containerID string) error
}
