package controller

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"river3.local/containment/apiclient"
)

// sessionMap is one snapshot of workload_id → newest active session, swapped whole
// by SyncSessions (CONTRACTS.md §1.4). It is read by the normalizer on every event
// and on every revalidation, so a session that ended or was revoked between the two
// changes the candidate's target and aborts the action rather than revoking the
// successor session.
type sessionMap struct {
	byWorkload map[string]boundSession
	syncedAt   time.Time
	total      int // active sessions the API returned, bound or not
}

type boundSession struct {
	ID        string
	Principal string
	StartedAt string
}

// sessionIdent mirrors the engine's identifier rule: a session id the engine would
// reject must never reach Identity.SessionID, or every event for that workload
// would error out of Evaluate instead of being decided.
var sessionIdent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// SyncSessions fetches the API's active sessions and swaps in the new map. On a
// fetch error the previous map stays in force (a transient API outage must not
// un-bind every session for one interval and make a revoke impossible); the error is
// returned for logging. A session the API no longer lists as active is gone after
// this call.
func (c *Controller) SyncSessions(ctx context.Context) error {
	if c.cfg.API == nil {
		return fmt.Errorf("session sync needs the API")
	}
	list, err := c.cfg.API.ActiveSessions(ctx)
	if err != nil {
		return fmt.Errorf("fetch active sessions: %w", err)
	}
	next := buildSessionMap(list, c.cfg.Clock())
	prev := c.sessions.Load()
	c.sessions.Store(next)
	if prev == nil || sessionsChanged(prev, next) {
		c.cfg.Log.Info("sessions.synced", "active", next.total, "bound_workloads", len(next.byWorkload))
	}
	return nil
}

// buildSessionMap keeps, per workload, the active session with the latest
// started_at (ties: the lexically greater id, so the choice is deterministic).
// Sessions whose ids the engine would refuse are skipped.
func buildSessionMap(list []apiclient.Session, now time.Time) *sessionMap {
	m := &sessionMap{byWorkload: map[string]boundSession{}, syncedAt: now}
	for _, s := range list {
		if s.State != "active" {
			continue
		}
		m.total++
		if !sessionIdent.MatchString(s.ID) || !sessionIdent.MatchString(s.WorkloadID) {
			continue
		}
		cand := boundSession{ID: s.ID, Principal: s.Principal, StartedAt: s.StartedAt}
		cur, ok := m.byWorkload[s.WorkloadID]
		if !ok || newer(cand, cur) {
			m.byWorkload[s.WorkloadID] = cand
		}
	}
	return m
}

// newer orders by started_at as RFC 3339 when both parse, else by the raw string,
// then by id. The API emits RFC 3339 UTC; the fallback only keeps the choice stable.
func newer(a, b boundSession) bool {
	ta, ea := time.Parse(time.RFC3339Nano, a.StartedAt)
	tb, eb := time.Parse(time.RFC3339Nano, b.StartedAt)
	switch {
	case ea == nil && eb == nil && !ta.Equal(tb):
		return ta.After(tb)
	case a.StartedAt != b.StartedAt:
		return a.StartedAt > b.StartedAt
	}
	return a.ID > b.ID
}

func sessionsChanged(a, b *sessionMap) bool {
	if len(a.byWorkload) != len(b.byWorkload) {
		return true
	}
	for k, v := range a.byWorkload {
		if w, ok := b.byWorkload[k]; !ok || w.ID != v.ID {
			return true
		}
	}
	return false
}

// boundSession is the normalizer's session source: the newest active session for
// the asset, or "" when none is known (no map yet, or the API lists none).
func (c *Controller) boundSession(assetID string) string {
	m := c.sessions.Load()
	if m == nil {
		return ""
	}
	return m.byWorkload[assetID].ID
}

// SessionCounts is what /healthz reports about the session map.
func (c *Controller) SessionCounts() map[string]any {
	m := c.sessions.Load()
	if m == nil {
		return map[string]any{"synced": false, "active": 0, "bound_workloads": 0}
	}
	assets := make([]string, 0, len(m.byWorkload))
	for a := range m.byWorkload {
		assets = append(assets, a)
	}
	sort.Strings(assets)
	return map[string]any{"synced": true, "synced_at": m.syncedAt.UTC().Format(time.RFC3339), "active": m.total,
		"bound_workloads": len(m.byWorkload), "workloads": assets}
}

// RunSessionSync calls SyncSessions every interval until ctx ends (default 5 s).
func (c *Controller) RunSessionSync(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := c.SyncSessions(ctx); err != nil && ctx.Err() == nil {
			c.cfg.Log.Warn("sessions.sync", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
