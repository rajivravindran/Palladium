package controller

import (
	"context"
	"fmt"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/apiclient"
	"river3.local/containment/journal"
)

// OperatorOutcome is what happened to one operator request on this node.
type OperatorOutcome string

const (
	OpCompleted OperatorOutcome = "completed"
	OpFailed    OperatorOutcome = "failed"
	OpIgnored   OperatorOutcome = "ignored"   // not this node's workload, or not an executable action
	OpDuplicate OperatorOutcome = "duplicate" // already handled (webhook + poll both delivered it)
)

// HandleOperatorAction executes an authenticated operator request.
//
// Authentication is the transport's job and is complete before this is called:
// the request came either from GET /actions over our machine token, or from a
// webhook whose HMAC the server verified. The API itself only queues resume /
// terminate for principals holding the "act" permission, under their own name.
// Here we add what only the node can check: that the workload is ours, that the
// container is still the enrolled generation, and that the runtime really changed.
func (c *Controller) HandleOperatorAction(ctx context.Context, a apiclient.OperatorAction, source string) OperatorOutcome {
	log := c.cfg.Log.With("action_id", a.ID, "action", a.Action, "operator", a.Operator, "source", source)
	if a.Action != "resume" && a.Action != "terminate" && a.Action != "revoke_session" {
		return OpIgnored
	}
	w, ok := c.cfg.Registry.Get().Workload(a.WorkloadID)
	if !ok {
		return OpIgnored // another node's workload; the API fans out to every controller
	}
	j := c.cfg.Journal
	// The claim carries the request itself: after a crash the API's queue entry may
	// already be gone, and reconcileOperator needs to know what was asked of whom.
	request := map[string]any{"action": a.Action, "workload_id": a.WorkloadID, "operator": a.Operator, "source": source}
	if a.Action == "revoke_session" {
		request["session_id"] = a.SessionID
		request["incident_id"] = a.IncidentID
	}
	claimed, err := j.ClaimOperator(a.ID, request)
	if err != nil {
		log.Error("operator.journal", "err", err)
		return OpFailed
	}
	if !claimed {
		if o, ok := j.Operator(a.ID); ok && (o.Result == "completed" || o.Result == "failed") && !o.Reported {
			c.reportOperator(ctx, o)
		}
		return OpDuplicate
	}

	c.actMu.Lock()
	defer c.actMu.Unlock()

	var result OperatorOutcome
	var detail map[string]any
	if a.Action == "revoke_session" {
		result, detail = c.runOperatorRevoke(ctx, a)
	} else {
		result, detail = c.runOperator(ctx, a, w.ContainerID, w.Generation, w.Kind)
		detail["adapter"] = c.cfg.Adapter.Name()
	}
	detail["operator"] = a.Operator
	_ = j.FinishOperator(a.ID, string(result), detail)
	log.Info("operator.done", "result", result, "detail", detail)
	if c.cfg.API != nil {
		if o, ok := j.Operator(a.ID); ok {
			c.reportOperator(ctx, o)
		}
	}
	return result
}

func (c *Controller) runOperator(ctx context.Context, a apiclient.OperatorAction, cid, generation, kind string) (OperatorOutcome, map[string]any) {
	detail := map[string]any{}
	inspectCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	info, err := c.cfg.Adapter.Inspect(inspectCtx, cid)
	cancel()
	if err != nil {
		detail["reason"] = "runtime inspection failed: " + err.Error()
		return OpFailed, detail
	}
	detail["before"] = string(info.Status)
	if info.Status != adapter.Missing && (info.ContainerID != cid || info.Generation != generation) {
		detail["reason"] = "STALE_GENERATION: runtime container differs from enrollment"
		return OpFailed, detail
	}

	start := time.Now()
	var want adapter.Status
	switch a.Action {
	case "resume":
		want = adapter.Running
		switch info.Status {
		case adapter.Running:
			detail["note"] = "already running"
			detail["workload_state"] = "running"
			return OpCompleted, detail
		case adapter.Paused:
			callCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
			err = c.cfg.Adapter.Resume(callCtx, cid)
			cancel()
		default:
			detail["reason"] = "container is " + string(info.Status) + "; only a paused container can be resumed"
			return OpFailed, detail
		}
	case "terminate":
		want = adapter.Exited
		if kind != "ai_worker" {
			detail["reason"] = "only dedicated ai_worker containers may be terminated"
			return OpFailed, detail
		}
		if info.Status == adapter.Exited || info.Status == adapter.Missing {
			detail["note"] = "already stopped"
			detail["workload_state"] = "terminated"
			return OpCompleted, detail
		}
		// A stop returns only once the container is down: SIGTERM, then SIGKILL after
		// the grace period. The budget must cover the grace period or every workload
		// that ignores SIGTERM would be journaled as a timed-out adapter call.
		callCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout+adapter.StopGrace)
		err = c.cfg.Adapter.Terminate(callCtx, cid)
		cancel()
	}
	detail["latency_ms"] = float64(time.Since(start).Microseconds()) / 1000

	state, vd := c.verify(ctx, cid, generation, want, err)
	for k, v := range vd {
		detail[k] = v
	}
	switch state {
	case journal.Verified:
		if want == adapter.Running {
			detail["workload_state"] = "running"
		} else {
			detail["workload_state"] = "terminated"
		}
		return OpCompleted, detail
	case journal.Unknown:
		detail["workload_state"] = "unknown"
	}
	return OpFailed, detail
}

// runOperatorRevoke executes an operator's revoke_session (CONTRACTS.md §2.2). The
// session is the incident's binding as the API delivered it in the action payload,
// never anything the operator typed, and never guessed from the current session map:
// an operator revokes the session they were looking at on the incident. Without a
// session adapter there is nothing that can carry it out; without a session id there
// is nothing to revoke (the API refuses such requests with 409, so this is a stale
// delivery). Settled by inspection exactly like the automatic path.
func (c *Controller) runOperatorRevoke(ctx context.Context, a apiclient.OperatorAction) (OperatorOutcome, map[string]any) {
	detail := map[string]any{"session_id": a.SessionID}
	if c.cfg.Sessions == nil {
		detail["reason"] = "ADAPTER_UNAVAILABLE: no session adapter configured on this node (-session-adapter gateway)"
		return OpFailed, detail
	}
	detail["adapter"] = c.cfg.Sessions.Name()
	if a.SessionID == "" {
		detail["reason"] = "no session bound to the incident; nothing to revoke"
		return OpFailed, detail
	}
	if !sessionIdent.MatchString(a.SessionID) {
		detail["reason"] = "malformed session id in the action payload"
		return OpFailed, detail
	}
	inspectCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	before, err := c.cfg.Sessions.InspectSession(inspectCtx, a.SessionID)
	cancel()
	if err != nil {
		detail["reason"] = "gateway inspection failed: " + err.Error()
		return OpFailed, detail
	}
	detail["before"] = string(before.State)
	if before.Principal != "" {
		detail["principal"] = before.Principal
	}
	switch before.State {
	case adapter.SessionRevoked:
		detail["note"] = "already revoked"
		detail["session_state"] = string(before.State)
		return OpCompleted, detail
	case adapter.SessionUnknown:
		detail["reason"] = "gateway does not know this session; nothing to revoke"
		return OpFailed, detail
	}

	reason := truncate(fmt.Sprintf("river3 operator %s: %s (incident %s)", a.Operator, a.Reason, a.IncidentID), 512)
	start := time.Now()
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	claimed, callErr := c.cfg.Sessions.Revoke(callCtx, a.SessionID, reason, a.IncidentID, "operator_"+a.ID)
	cancel()
	detail["latency_ms"] = float64(time.Since(start).Microseconds()) / 1000

	state, vd := c.verifySession(ctx, a.SessionID, claimed, callErr)
	for k, v := range vd {
		detail[k] = v
	}
	if state == journal.Verified {
		return OpCompleted, detail
	}
	return OpFailed, detail
}

// reconcileOperator settles an operator request that was claimed but never finished:
// the previous process died between ClaimOperator and FinishOperator, possibly with
// the adapter call half way out. The claim is durable, so a redelivery from the API
// is a duplicate and would be dropped; without this the request would stay
// "handling" forever and the operator would never see a result.
//
// What happens next depends on what the action does to the workload:
//
//   - resume is re-executed, through the same runOperator flow a fresh request takes.
//     It is idempotent (the flow inspects first: already running → completed, a stale
//     generation → failed, only a paused container is unpaused) and it is the one
//     operator action that restores service rather than removing it; the next violation
//     pauses the container again. Failing it instead would leave a workload frozen that
//     an authenticated operator explicitly asked to run, until someone notices the
//     failed row and asks a second time.
//   - terminate and revoke_session are never re-run. Both are destructive, the restart
//     may be minutes later and the incident may have moved on, so a kill or a revoke
//     must only happen when an operator asked for it in the state they were looking at.
//     They are settled by inspection only: completed when the runtime already shows the
//     asked-for state (the call went out before the crash), otherwise failed with the
//     reason "controller restarted mid-action" so the operator can ask again.
//
// Either way the result is journaled and reported through the outbox like any other.
func (c *Controller) reconcileOperator(ctx context.Context, o journal.OperatorView) {
	j := c.cfg.Journal
	detail := map[string]any{"reason": "controller restarted mid-action", "reconciled": true, "adapter": c.cfg.Adapter.Name()}
	for _, k := range []string{"action", "workload_id", "operator"} {
		if v, ok := o.Detail[k]; ok {
			detail[k] = v
		}
	}
	result := OpFailed
	action, _ := o.Detail["action"].(string)
	wid, _ := o.Detail["workload_id"].(string)
	operator, _ := o.Detail["operator"].(string)
	if action == "resume" {
		if w, ok := c.cfg.Registry.Get().Workload(wid); ok {
			req := apiclient.OperatorAction{ID: o.ActionID, WorkloadID: wid, Action: "resume", Operator: operator}
			c.actMu.Lock()
			result, detail = c.runOperator(ctx, req, w.ContainerID, w.Generation, w.Kind)
			c.actMu.Unlock()
			detail["adapter"] = c.cfg.Adapter.Name()
			detail["operator"] = operator
			detail["reconciled"] = true
			detail["note"] = "re-executed after controller restart"
			if before, _ := detail["before"].(string); before == string(adapter.Running) {
				detail["note"] = "settled after controller restart: runtime already shows running"
			}
		} else {
			detail["reason"] = "controller restarted mid-action; workload is no longer enrolled on this node"
		}
		_ = j.FinishOperator(o.ActionID, string(result), detail)
		c.cfg.Log.Warn("reconcile.operator", "action_id", o.ActionID, "result", result, "detail", detail)
		return
	}
	if action == "revoke_session" {
		// Same rule: inspection only. The gateway either shows the session revoked (the
		// call went out before the crash) or it does not; the revoke is never re-sent.
		sid, _ := o.Detail["session_id"].(string)
		detail["session_id"] = sid
		if c.cfg.Sessions != nil && sid != "" {
			detail["adapter"] = c.cfg.Sessions.Name()
			inspectCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
			info, err := c.cfg.Sessions.InspectSession(inspectCtx, sid)
			cancel()
			switch {
			case err != nil:
				detail["inspect_error"] = err.Error()
			case info.State == adapter.SessionRevoked:
				result = OpCompleted
				detail["session_state"] = string(info.State)
				detail["note"] = "settled after controller restart: gateway already shows revoked"
				delete(detail, "reason")
			default:
				detail["session_state"] = string(info.State)
			}
		}
		_ = j.FinishOperator(o.ActionID, string(result), detail)
		c.cfg.Log.Warn("reconcile.operator", "action_id", o.ActionID, "result", result, "detail", detail)
		return
	}
	// terminate: inspection only, never a second stop (see above).
	if w, ok := c.cfg.Registry.Get().Workload(wid); ok && action == "terminate" {
		inspectCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
		info, err := c.cfg.Adapter.Inspect(inspectCtx, w.ContainerID)
		cancel()
		switch {
		case err != nil:
			detail["inspect_error"] = err.Error()
		case info.ContainerID != w.ContainerID || (info.Status != adapter.Missing && info.Generation != w.Generation):
			detail["observed"] = map[string]any{"status": string(info.Status), "generation": info.Generation}
			detail["reason"] = "controller restarted mid-action; runtime shows a different container or generation"
		case info.Status == adapter.Exited || info.Status == adapter.Missing:
			result, detail["workload_state"] = OpCompleted, "terminated"
			detail["note"] = "settled after controller restart: runtime already shows " + string(info.Status)
			delete(detail, "reason")
		default:
			detail["observed"] = map[string]any{"status": string(info.Status), "generation": info.Generation}
		}
	}
	_ = j.FinishOperator(o.ActionID, string(result), detail)
	c.cfg.Log.Warn("reconcile.operator", "action_id", o.ActionID, "result", result, "detail", detail)
}

// PollOnce fetches queued operator requests from the API and handles them.
func (c *Controller) PollOnce(ctx context.Context) {
	if c.cfg.API == nil {
		return
	}
	for _, status := range []string{"requested", "delivered"} {
		acts, err := c.cfg.API.QueuedActions(ctx, status)
		if err != nil {
			c.cfg.Log.Warn("poll.failed", "status", status, "err", err.Error())
			continue
		}
		for _, a := range acts {
			c.HandleOperatorAction(ctx, a, "poll")
		}
	}
}

// RunLoops polls for operator requests and flushes the outbox until ctx ends.
func (c *Controller) RunLoops(ctx context.Context, poll, flush time.Duration) {
	pt := time.NewTicker(poll)
	ft := time.NewTicker(flush)
	defer pt.Stop()
	defer ft.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pt.C:
			c.PollOnce(ctx)
		case <-ft.C:
			c.Flush(ctx)
		}
	}
}
