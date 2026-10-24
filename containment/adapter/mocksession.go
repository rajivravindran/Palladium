package adapter

import (
	"context"
	"sync"

	policy "river3.local/policy"
)

// MockSessions is an in-memory gateway for tests. Its failure switches model the
// ways a gateway misbehaves: the revoke call fails, it "succeeds" but the session
// stays active, or inspection is unavailable afterwards.
type MockSessions struct {
	mu       sync.Mutex
	sessions map[string]SessionInfo
	calls    []string

	RevokeErr      error // Revoke returns this error
	RevokeNoEffect bool  // Revoke answers "revoked" but the state stays active
	InspectErr     error // InspectSession returns this error
}

func NewMockSessions() *MockSessions { return &MockSessions{sessions: map[string]SessionInfo{}} }

// Add registers a session the fake gateway knows.
func (m *MockSessions) Add(id, principal string, state SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = SessionInfo{ID: id, State: state, Principal: principal, StartedAt: "2026-10-22T08:00:00Z"}
}

// Calls returns the ordered log of mutating calls, e.g. "revoke:<id>".
func (m *MockSessions) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}

func (m *MockSessions) Name() string             { return "mock-gateway" }
func (m *MockSessions) Actions() []policy.Action { return []policy.Action{policy.Revoke} }

func (m *MockSessions) Revoke(_ context.Context, sessionID, _, _, _ string) (SessionState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "revoke:"+sessionID)
	if m.RevokeErr != nil {
		return "", m.RevokeErr
	}
	s, ok := m.sessions[sessionID]
	if !ok {
		return SessionUnknown, ErrSessionUnknown
	}
	if m.RevokeNoEffect {
		return SessionRevoked, nil
	}
	s.State = SessionRevoked
	m.sessions[sessionID] = s
	return SessionRevoked, nil
}

func (m *MockSessions) InspectSession(_ context.Context, sessionID string) (SessionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InspectErr != nil {
		return SessionInfo{}, m.InspectErr
	}
	s, ok := m.sessions[sessionID]
	if !ok {
		return SessionInfo{ID: sessionID, State: SessionUnknown}, nil
	}
	return s, nil
}
