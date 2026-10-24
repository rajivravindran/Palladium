package adapter

import (
	"context"
	"errors"
	"fmt"
	"sync"

	policy "river3.local/policy"
)

// Mock is an in-memory runtime for fixtures and tests. Its failure switches model
// the ways a real runtime misbehaves: the call fails, the call "succeeds" but the
// state did not change, inspection is unavailable, or the container was replaced.
type Mock struct {
	mu         sync.Mutex
	containers map[string]*Info
	calls      []string

	// Failure switches (set before the scenario runs).
	PauseErr      error // Pause returns this error
	PauseNoEffect bool  // Pause returns nil but the state stays running
	ResumeErr     error
	TerminateErr  error
	InspectErr    error // Inspect returns this error
	Unsupported   bool  // Actions() is empty: engine must block with ADAPTER_UNAVAILABLE
	// InspectHook runs (unlocked) before each Inspect with the 1-based call number,
	// so a test can change the runtime between evaluation and revalidation.
	InspectHook func(call int)
	// InspectErrAfterMutation makes Inspect fail once any mutating call happened:
	// "the pause went out, then the runtime stopped answering".
	InspectErrAfterMutation error
	inspects                int
	mutated                 bool
}

func NewMock() *Mock { return &Mock{containers: map[string]*Info{}} }

// Add enrolls a container in the fake runtime.
func (m *Mock) Add(containerID, generation string, status Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.containers[containerID] = &Info{ContainerID: containerID, Generation: generation, Status: status}
}

// Replace simulates a restart: same id, new generation, running.
func (m *Mock) Replace(containerID, newGeneration string) {
	m.Add(containerID, newGeneration, Running)
}

// Remove simulates the container disappearing.
func (m *Mock) Remove(containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.containers, containerID)
}

// Calls returns the ordered log of mutating calls, e.g. "pause:<id>".
func (m *Mock) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}

func (m *Mock) Name() string { return "mock" }

func (m *Mock) Actions() []policy.Action {
	if m.Unsupported {
		return nil
	}
	return []policy.Action{policy.Pause}
}

func (m *Mock) Inspect(_ context.Context, id string) (Info, error) {
	m.mu.Lock()
	m.inspects++
	n := m.inspects
	hook := m.InspectHook
	m.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InspectErr != nil {
		return Info{}, m.InspectErr
	}
	if m.mutated && m.InspectErrAfterMutation != nil {
		return Info{}, m.InspectErrAfterMutation
	}
	c, ok := m.containers[id]
	if !ok {
		return Info{ContainerID: id, Status: Missing}, nil
	}
	return *c, nil
}

func (m *Mock) Pause(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "pause:"+id)
	m.mutated = true
	if m.PauseErr != nil {
		return m.PauseErr
	}
	c, ok := m.containers[id]
	if !ok {
		return fmt.Errorf("mock: no such container")
	}
	if c.Status != Running {
		return fmt.Errorf("mock: container is %s, cannot pause", c.Status)
	}
	if !m.PauseNoEffect {
		c.Status = Paused
	}
	return nil
}

func (m *Mock) Resume(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "resume:"+id)
	m.mutated = true
	if m.ResumeErr != nil {
		return m.ResumeErr
	}
	c, ok := m.containers[id]
	if !ok {
		return fmt.Errorf("mock: no such container")
	}
	if c.Status != Paused {
		return fmt.Errorf("mock: container is %s, cannot resume", c.Status)
	}
	c.Status = Running
	return nil
}

func (m *Mock) Terminate(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "terminate:"+id)
	m.mutated = true
	if m.TerminateErr != nil {
		return m.TerminateErr
	}
	c, ok := m.containers[id]
	if !ok {
		return errors.New("mock: no such container")
	}
	c.Status = Exited
	return nil
}
