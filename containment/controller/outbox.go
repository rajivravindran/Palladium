package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"river3.local/containment/apiclient"
	"river3.local/containment/journal"
	policy "river3.local/policy"
	policyreport "river3.local/policy/report"
)

// Flush pushes every unreported decision, response and operator result to the
// API. It is idempotent and safe to call often; each step is journaled when the
// API acknowledges it, so a crash in the middle just repeats the remaining steps.
func (c *Controller) Flush(ctx context.Context) {
	if c.cfg.API == nil {
		return
	}
	for _, ev := range c.cfg.Journal.Pending() {
		c.flushEvent(ctx, ev.EventID)
	}
	for _, o := range c.cfg.Journal.UnreportedOperators() {
		c.reportOperator(ctx, o)
	}
}

// acquire marks key as being flushed by this goroutine. It returns false when
// another pass already holds it; that pass will journal whatever the API
// acknowledges, so the caller simply skips the key this round rather than waiting.
// The lock is per key, not global, so a slow API call for one event does not stall
// the rest of the outbox.
func (c *Controller) acquire(key string) bool {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	if c.flushing[key] {
		return false
	}
	c.flushing[key] = true
	return true
}

func (c *Controller) release(key string) {
	c.flushMu.Lock()
	delete(c.flushing, key)
	c.flushMu.Unlock()
}

func (c *Controller) flushEvent(ctx context.Context, eventID string) {
	if c.cfg.API == nil {
		return
	}
	if !c.acquire("event:" + eventID) {
		return
	}
	defer c.release("event:" + eventID)
	j := c.cfg.Journal
	// Read the view AFTER taking the key: a pass that just finished may have
	// created the incident, and acting on a stale view is the double POST.
	ev, ok := j.Event(eventID)
	if !ok || ev.Decision == nil || ev.Orphaned {
		return
	}
	st, err := decodeStored(ev.Decision)
	if err != nil {
		c.cfg.Log.Error("outbox.decode", "event", eventID, "err", err)
		return
	}
	log := c.cfg.Log.With("event", eventID)

	if !ev.Report {
		return // IN_SCOPE or unreported UNKNOWN: nothing goes to the API
	}
	if ev.IncidentID == "" {
		if !c.ensureWorkload(ctx, st) {
			return
		}
		// Write the intent first so that a 409 after a crash is recognised as "we did
		// post it, we just never learned the id" instead of a mystery.
		if err := j.MarkIncidentAttempt(eventID); err != nil {
			log.Error("outbox.journal", "err", err)
			return
		}
		id, err := c.cfg.API.CreateIncident(ctx, st.Incident)
		if apiclient.IsStatus(err, http.StatusConflict) {
			// The API already holds this event (the sensor's own history sink usually
			// gets there first). Attach to it by id instead of embedding it again.
			id, err = c.cfg.API.CreateIncident(ctx, attachExisting(st.Incident))
		}
		switch {
		case err == nil:
			_ = j.MarkIncidentCreated(eventID, id)
			ev.IncidentID = id
			log.Info("outbox.incident_created", "incident", id)
		case apiclient.IsStatus(err, http.StatusConflict):
			// The event is already attached to another incident (an earlier attempt of
			// ours whose reply was lost, or the policy-eval reporter). Without a read
			// permission we cannot learn that id, so the response can only be
			// reconciled by hand. Loud, explicit, final.
			_ = j.MarkOrphaned(eventID, err.Error())
			log.Error("outbox.orphaned", "err", err.Error(),
				"hint", "incident exists at the API but this controller does not know its id; response must be reconciled manually")
			return
		default:
			log.Warn("outbox.incident_failed", "err", err.Error())
			return
		}
	}

	if ev.HasResponse && !ev.ResponseDone {
		a, ok := j.Action(ev.ActionKey)
		if !ok {
			return
		}
		adapterName := c.cfg.Adapter.Name()
		if a.Action == string(policy.Revoke) && c.cfg.Sessions != nil {
			adapterName = c.cfg.Sessions.Name()
		}
		body := responseFor(a, adapterName)
		if err := c.cfg.API.PatchResponse(ctx, ev.IncidentID, body); err != nil {
			log.Warn("outbox.response_failed", "err", err.Error())
			return
		}
		_ = j.MarkResponseReported(eventID)
		log.Info("outbox.response_reported", "incident", ev.IncidentID, "state", a.State)
	}
}

// attachExisting rewrites an incident body to reference its events by id
// (IncidentIn.event_ids) instead of embedding them (IncidentIn.events).
func attachExisting(inc policyreport.IncidentIn) map[string]any {
	b, _ := json.Marshal(inc)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	ids := make([]string, 0, len(inc.Events))
	for _, e := range inc.Events {
		ids = append(ids, e.ID)
	}
	delete(m, "events")
	m["event_ids"] = ids
	return m
}

// responseFor maps a journaled action to the API's response patch. Only a VERIFIED
// action changes the incident status. A verified pause also freezes the workload; a
// verified revoke (CONTRACTS.md §2.3: response.action "REVOKE_SESSION",
// response.state, response.session_id) leaves the workload state alone — the
// container keeps running, it is the session the API marks revoked — and an
// unknown revoke says nothing about the workload either.
func responseFor(a journal.ActionView, adapterName string) apiclient.ResponseUpdate {
	resp := map[string]any{
		"action":          a.Action,
		"state":           strings.ToLower(string(a.State)),
		"adapter":         adapterName,
		"idempotency_key": a.Key,
	}
	if a.Latency > 0 {
		resp["latency_ms"] = a.Latency
	}
	for k, v := range a.Detail {
		resp[k] = v
	}
	out := apiclient.ResponseUpdate{Response: resp}
	if a.Action == string(policy.Revoke) {
		if a.State == journal.Verified {
			out.Status = "contained"
		}
		return out
	}
	switch a.State {
	case journal.Verified:
		out.Status = "contained"
		out.WorkloadState = "frozen"
	case journal.Unknown:
		out.WorkloadState = "unknown"
	}
	return out
}

func (c *Controller) ensureWorkload(ctx context.Context, st stored) bool {
	asset := st.Incident.WorkloadID
	c.enrolledMu.Lock()
	done := c.enrolled[asset]
	c.enrolledMu.Unlock()
	if done {
		return true
	}
	w, ok := c.cfg.Registry.Get().Workload(asset)
	if !ok {
		return false
	}
	team := w.Team
	if team == "" {
		team = st.Team // the sensor's label copy; the API only lets it fill an empty team
	}
	err := c.cfg.API.EnsureWorkload(ctx, apiclient.Workload{ID: w.AssetID, Name: w.Name, Profile: w.Profile, Kind: w.Kind, Team: team})
	if err != nil {
		c.cfg.Log.Warn("outbox.workload_failed", "asset", asset, "err", err.Error())
		return false
	}
	c.enrolledMu.Lock()
	c.enrolled[asset] = true
	c.enrolledMu.Unlock()
	return true
}

func (c *Controller) reportOperator(ctx context.Context, o journal.OperatorView) {
	if !c.acquire("operator:" + o.ActionID) {
		return
	}
	defer c.release("operator:" + o.ActionID)
	if cur, ok := c.cfg.Journal.Operator(o.ActionID); !ok || cur.Reported {
		return
	}
	body := apiclient.ActionResult{Status: o.Result, Detail: o.Detail}
	if ws, ok := o.Detail["workload_state"].(string); ok {
		body.WorkloadState = ws
	}
	err := c.cfg.API.PostResult(ctx, o.ActionID, body)
	switch {
	case err == nil, apiclient.IsStatus(err, http.StatusConflict): // 409: the API already has a result
		_ = c.cfg.Journal.MarkOperatorReported(o.ActionID)
		c.cfg.Log.Info("operator.reported", "action_id", o.ActionID, "result", o.Result)
	default:
		c.cfg.Log.Warn("operator.report_failed", "action_id", o.ActionID, "err", err.Error())
	}
}
