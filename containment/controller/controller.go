// Package controller executes the containment loop around the policy engine.
//
//	authenticated sensor event
//	  → normalize (trusted registry + live inspection)
//	  → engine.Evaluate, deterministic rules only
//	  → not a VIOLATION and a guard is configured? guard.Assess → engine.Evaluate again
//	  → durable decision
//	  → candidate? reserve idempotency key → refresh context → engine.Revalidate
//	  → adapter call → inspect the runtime → record VERIFIED | FAILED | UNKNOWN
//	  → report incident + verified response to the API (retried until acknowledged)
//
// Operator resume/terminate requests arrive through the API (poll or signed
// webhook), are deduplicated durably, checked against the enrolled generation,
// executed through the same adapter, verified by inspection and reported back.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/apiclient"
	"river3.local/containment/guard"
	"river3.local/containment/journal"
	"river3.local/containment/normalize"
	"river3.local/containment/registry"
	policy "river3.local/policy"
	"river3.local/policy/report"
)

type Config struct {
	Engine   *policy.Engine
	Profiles map[string]*policy.Profile
	Registry *registry.Holder
	Adapter  adapter.Adapter
	Journal  *journal.Journal
	API      *apiclient.Client // nil = offline; decisions and actions still happen, nothing is reported
	Guard    guard.Guard       // nil = no model guard (-guard off); Laya or LLM; assessments are advisory either way
	// Sessions is the session adapter (CONTRACTS.md §2.1, -session-adapter gateway).
	// nil = no way to revoke: the engine blocks REVOKE_SESSION with ADAPTER_UNAVAILABLE
	// and operator revoke_session requests fail with that reason.
	Sessions adapter.SessionAdapter
	// Egress resolves egress_allowed_domains into the enforced engine (§5). nil = off.
	Egress        *Egress
	ReportUnknown bool
	ActionTimeout time.Duration // per adapter call; default 5 s
	Clock         func() time.Time
	Log           *slog.Logger
	// HeartbeatWithin: a workload is unhealthy if its sensor has been silent this long. 0 = off.
	HeartbeatWithin time.Duration
	// PolicyCache: where SyncPolicy keeps the last applied API bundle. "" = no cache.
	PolicyCache string
}

type Controller struct {
	cfg  Config
	norm *normalize.Normalizer
	pol  atomic.Pointer[Policy] // swapped whole by SetPolicy; read once per decision

	// sessions: workload → newest active session from the API (§1.4), swapped whole
	// by SyncSessions; nil until the first successful sync (then no session is bound).
	sessions atomic.Pointer[sessionMap]

	syncMu     sync.Mutex // one policy sync at a time
	seenRev    string     // last bundle revision fetched from the API
	syncErr    string     // why seenRev was refused, if it was
	reported   string     // last report the API acknowledged, to avoid re-sending it
	reportedAt time.Time  // re-sent every minute anyway, so the console can tell a silent controller

	actMu sync.Mutex // one runtime mutation at a time on this node

	hbMu       sync.Mutex
	heartbeats map[string]time.Time
	started    time.Time // baseline for a sensor never heard from: it cannot have been silent longer than we have listened

	enrolledMu sync.Mutex
	enrolled   map[string]bool // assets whose workload record reached the API this process

	// flushMu/flushing: at most one outbox pass per event (and per operator result) at
	// a time. HandleEvent flushes its own event while the periodic Flush (and Start's
	// Flush) may scan the same pending list; two passes seeing IncidentID == "" would
	// both POST the incident, the second get 409, retry by id, get 409 again and mark
	// the event orphaned, never to be retried. See flushEvent.
	flushMu  sync.Mutex
	flushing map[string]bool

	// reload: the registry file watcher (reload.go), nil until WatchRegistry.
	reload atomic.Pointer[RegistryReload]
}

// Outcome summarises what HandleEvent did; it is also what the dev event endpoint returns.
type Outcome struct {
	EventID    string          `json:"event_id"`
	Status     policy.Status   `json:"status"`
	Action     policy.Action   `json:"action"`
	Blockers   []string        `json:"blockers"`
	Candidate  bool            `json:"candidate"`
	Duplicate  bool            `json:"duplicate,omitempty"`
	Unenrolled bool            `json:"unenrolled,omitempty"`
	Response   *journal.State  `json:"response_state,omitempty"`
	Key        string          `json:"idempotency_key,omitempty"`
	IncidentID string          `json:"incident_id,omitempty"`
	Notes      []string        `json:"notes"`
	Decision   policy.Decision `json:"-"`
}

// stored is what the decision journal record holds: the decision plus the exact
// incident body, so the outbox can retry creation after a restart.
type stored struct {
	Decision policy.Decision   `json:"decision"`
	Incident report.IncidentIn `json:"incident"`
	Report   bool              `json:"report"`         // false for IN_SCOPE / unreported UNKNOWN
	Team     string            `json:"team,omitempty"` // for the workload registration (CONTRACTS.md §6); registry team, else the sensor's label
}

func New(cfg Config) (*Controller, error) {
	if cfg.Engine == nil || cfg.Registry == nil || cfg.Adapter == nil || cfg.Journal == nil || len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("controller: engine, profiles, registry, adapter and journal are required")
	}
	if cfg.ActionTimeout <= 0 {
		cfg.ActionTimeout = 5 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Egress != nil && cfg.Egress.Log == nil {
		cfg.Egress.Log = cfg.Log
	}
	c := &Controller{cfg: cfg, heartbeats: map[string]time.Time{}, enrolled: map[string]bool{}, flushing: map[string]bool{}, started: cfg.Clock()}
	c.SetPolicy(&Policy{Engine: cfg.Engine, Profiles: cfg.Profiles})
	c.norm = &normalize.Normalizer{Registry: cfg.Registry, Adapter: cfg.Adapter, Sessions: cfg.Sessions, HeartbeatWithin: cfg.HeartbeatWithin}
	c.norm.SetHeartbeat(c.lastHeartbeat)
	c.norm.SetSession(c.boundSession)
	return c, nil
}

func (c *Controller) Journal() *journal.Journal  { return c.cfg.Journal }
func (c *Controller) Registry() *registry.Holder { return c.cfg.Registry }

// Heartbeat records that an authenticated sensor was heard from.
func (c *Controller) Heartbeat(sensor string) {
	c.hbMu.Lock()
	c.heartbeats[sensor] = c.cfg.Clock()
	c.hbMu.Unlock()
}

// lastHeartbeat is the normalizer's liveness source: when the sensor last spoke
// BEFORE the event being normalized. A sensor this process has never heard from is
// measured from process start, so a controller that has listened for less than
// HeartbeatWithin does not block a sensor's first event, while one that has been up
// for an hour without hearing from the sensor correctly treats it as silent.
func (c *Controller) lastHeartbeat(sensor string) time.Time {
	c.hbMu.Lock()
	defer c.hbMu.Unlock()
	if t, ok := c.heartbeats[sensor]; ok {
		return t
	}
	return c.started
}

// Start reconciles whatever the previous process left behind, then flushes the
// outbox. Call once before serving events.
func (c *Controller) Start(ctx context.Context) error {
	for _, a := range c.cfg.Journal.InFlight() {
		c.reconcile(ctx, a)
	}
	// Operator claims are durable too: one left "handling" would otherwise never get
	// a result, and the API's redelivery would be dropped as a duplicate.
	for _, o := range c.cfg.Journal.HandlingOperators() {
		c.reconcileOperator(ctx, o)
	}
	c.Flush(ctx)
	return nil
}

// ------------------------------------------------------------------ events

// HandleEvent runs the full loop for one event.
func (c *Controller) HandleEvent(ctx context.Context, env normalize.Envelope) (Outcome, error) {
	now := c.cfg.Clock()
	// The heartbeat check inside Normalize must see the PREVIOUS message from this
	// sensor, not this one: recording first would make a sensor that was silent for
	// an hour look healthy the instant it speaks again, and the check could never fail.
	res, err := c.norm.Normalize(ctx, env, now)
	if env.Authentic {
		c.Heartbeat(env.Sensor.Name)
	}
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{EventID: res.Event.ID, Notes: res.Notes}
	if !res.Enrolled {
		// No profile binding → nothing to evaluate against. Alert in the log; the
		// API cannot hold an incident for a workload it does not know.
		out.Unenrolled = true
		out.Status = policy.Unknown
		out.Action = policy.Alert
		c.cfg.Log.Warn("event.unenrolled", "event", res.Event.ID, "workload", env.Raw.Facts.Workload.ID)
		return out, nil
	}
	pol := c.pol.Load()
	prof, ok := pol.Profiles[res.Workload.Profile]
	if !ok {
		return out, fmt.Errorf("workload %s is bound to unknown profile %q", res.Workload.AssetID, res.Workload.Profile)
	}
	res.WithProfileVersion(prof.Version)

	// The deterministic engine decides first, with no model assessments. A
	// VIOLATION it finds on its own is final: Laya is advisory, so a model that
	// takes seconds (or is down) must never sit between a decoy read and the pause.
	d, err := pol.Engine.Evaluate(res.Event, res.Context)
	if err != nil {
		// Coverage/config problem: alert, never continue automatically.
		c.cfg.Log.Error("evaluate.error", "event", res.Event.ID, "err", err)
		return out, err
	}

	// Laya: two separate channels, verified by the adapter, advisory to the engine.
	// Consulted only when the deterministic rules did not already find a violation,
	// so it can raise IN_SCOPE to REVIEW (or to a candidate via on_structural_guard)
	// but never delays or dilutes a deterministic finding. res.Context.Assessments
	// stays nil otherwise, and act() revalidates with exactly that context, so the
	// candidate the engine issued is the one Revalidate recomputes.
	var guardFacts map[string]any
	if c.cfg.Guard != nil {
		guardFacts = map[string]any{"name": c.cfg.Guard.Name(), "consulted": false}
		if d.Status != policy.Violation {
			assessments := c.cfg.Guard.Assess(ctx, guard.Input{Event: res.Event, Identity: res.Context.Identity,
				Profile: prof.Name, FactsA: res.Facts, PayloadB: res.Payload})
			res.Context.Assessments = assessments
			verdicts := make([]map[string]any, 0, len(assessments))
			for _, a := range assessments {
				verdicts = append(verdicts, map[string]any{"channel": a.Channel, "verdict": string(a.Verdict), "verified": a.Verified})
			}
			guardFacts["consulted"] = true
			guardFacts["assessments"] = verdicts
			// Laya learns the server-reported model name from the reply, so re-read
			// Name() now that the guard has answered.
			guardFacts["name"] = c.cfg.Guard.Name()
			// The model calls may have taken several seconds (two sequential calls,
			// each up to -guard-timeout). The candidate lease (ActionTTL, 5 s) runs
			// from Context.Now, so it must be the moment the engine decides, not the
			// moment the event arrived; otherwise every post-guard candidate reaches
			// Revalidate already expired. Only Now moves: the event's ObservedAt is
			// untouched, so STALE_EVENT still measures the event's true age (which
			// genuinely includes the time the model took).
			res.Context.Now = c.cfg.Clock()
			d, err = pol.Engine.Evaluate(res.Event, res.Context)
			if err != nil {
				c.cfg.Log.Error("evaluate.error", "event", res.Event.ID, "err", err)
				return out, err
			}
		} else {
			guardFacts["reason"] = "deterministic violation; the guard is advisory and never delays containment"
		}
	}
	out.Decision, out.Status, out.Action, out.Blockers = d, d.Status, d.Action, d.Blockers
	out.Candidate = d.Candidate != nil

	inc := report.BuildIncident(res.Event, d, prof.Kind)
	inc.Events[0].Facts = res.Facts
	inc.Events[0].Payload = res.Payload
	if guardFacts != nil {
		inc.Events[0].Facts["guard"] = guardFacts
	}
	if len(res.Notes) > 0 {
		inc.Reason = truncate(inc.Reason+" Normalizer: "+joinNotes(res.Notes), 2000)
	}
	inc.Demo = env.Provenance != policy.Live
	shouldReport := d.Status != policy.InScope && (d.Status != policy.Unknown || c.cfg.ReportUnknown)

	fresh, err := c.cfg.Journal.RecordDecision(res.Event.ID, stored{Decision: d, Incident: inc, Report: shouldReport, Team: res.Team}, shouldReport)
	if err != nil {
		return out, err
	}
	if !fresh {
		out.Duplicate = true
		c.cfg.Log.Info("event.duplicate", "event", res.Event.ID)
		if ev, ok := c.cfg.Journal.Event(res.Event.ID); ok {
			out.IncidentID = ev.IncidentID
			if a, ok := c.cfg.Journal.Action(ev.ActionKey); ok {
				st := a.State
				out.Response, out.Key = &st, a.Key
			}
		}
		return out, nil
	}
	c.cfg.Log.Info("decision", "event", res.Event.ID, "asset", res.Workload.AssetID, "status", d.Status,
		"recommended", d.RecommendedAction, "action", d.Action, "blockers", d.Blockers, "candidate", d.Candidate != nil)

	if d.Candidate != nil {
		st := c.act(ctx, env, res, d)
		out.Response, out.Key = &st, d.Candidate.IdempotencyKey
	}
	c.flushEvent(ctx, res.Event.ID)
	if ev, ok := c.cfg.Journal.Event(res.Event.ID); ok {
		out.IncidentID = ev.IncidentID
	}
	return out, nil
}

// act performs one automatic action for a fresh candidate and returns its final state.
func (c *Controller) act(ctx context.Context, env normalize.Envelope, res normalize.Result, d policy.Decision) journal.State {
	cand := *d.Candidate
	j := c.cfg.Journal
	log := c.cfg.Log.With("event", res.Event.ID, "asset", res.Workload.AssetID, "key", cand.IdempotencyKey[:19])

	c.actMu.Lock()
	defer c.actMu.Unlock()

	view, err := j.Reserve(cand.IdempotencyKey, string(cand.Action), cand.Target.ContainerID, cand.Target.AssetID, res.Event.ID)
	if errors.Is(err, journal.ErrDuplicate) {
		log.Info("action.duplicate", "state", view.State)
		if !view.State.Terminal() {
			c.reconcile(ctx, view)
			view, _ = j.Action(cand.IdempotencyKey)
		}
		return view.State
	}
	if err != nil {
		log.Error("action.reserve_failed", "err", err)
		return journal.Unknown
	}

	// Refresh everything the engine gates on and ask it again, right before acting.
	now := c.cfg.Clock()
	fresh, err := c.norm.Normalize(ctx, env, now)
	if err == nil {
		fresh.WithProfileVersion(res.Context.ProfileVersion)
		fresh.Context.Assessments = res.Context.Assessments // same evidence, re-checked against fresh runtime state
		// The current set, not the one that decided: a policy change in between aborts the action.
		err = c.pol.Load().Engine.Revalidate(cand, fresh.Event, fresh.Context)
	}
	if err != nil {
		detail := map[string]any{"reason": err.Error(), "notes": fresh.Notes}
		_ = j.Transition(cand.IdempotencyKey, journal.Aborted, detail, 0)
		log.Warn("action.aborted", "reason", err.Error())
		return journal.Aborted
	}
	switch cand.Action {
	case policy.Pause:
		return c.pauseContainer(ctx, cand, log)
	case policy.Revoke:
		return c.revokeSession(ctx, cand, res, d, log)
	}
	// The engine only emits what an adapter advertises. Defensive, not expected.
	_ = j.Transition(cand.IdempotencyKey, journal.Aborted, map[string]any{"reason": "action not implemented by this controller"}, 0)
	return journal.Aborted
}

// pauseContainer is the PAUSE_CONTAINER leg of act(): the reserved candidate is
// executed through the runtime adapter and settled by inspecting the container.
func (c *Controller) pauseContainer(ctx context.Context, cand policy.Candidate, log *slog.Logger) journal.State {
	j := c.cfg.Journal
	if err := j.Transition(cand.IdempotencyKey, journal.Executing, nil, 0); err != nil {
		log.Error("action.journal", "err", err)
		return journal.Unknown
	}

	start := time.Now()
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	callErr := c.cfg.Adapter.Pause(callCtx, cand.Target.ContainerID)
	cancel()
	latency := float64(time.Since(start).Microseconds()) / 1000

	state, detail := c.verify(ctx, cand.Target.ContainerID, cand.Target.Generation, adapter.Paused, callErr)
	detail["adapter"] = c.cfg.Adapter.Name()
	_ = j.Transition(cand.IdempotencyKey, state, detail, latency)
	log.Info("action.done", "state", state, "latency_ms", latency, "detail", detail)
	return state
}

// revokeSession is the REVOKE_SESSION leg of act() (CONTRACTS.md §2.3). The session
// is the one the candidate's identity carries, which Revalidate just confirmed is
// still the newest active session the API binds to this workload; the reason names
// the rule so the gateway's own log says why. The gateway's reply is a claim; the
// state is settled by InspectSession afterwards (verifySession).
//
// The gateway request's incident_id carries the evidence event id: at this point the
// incident does not exist yet, because the API is deliberately not in the containment
// path (the outbox creates the incident after the action, retrying through outages).
// The idempotency_key in the same request is also written into the incident's
// response, so the two records can be joined either way.
func (c *Controller) revokeSession(ctx context.Context, cand policy.Candidate, res normalize.Result, d policy.Decision, log *slog.Logger) journal.State {
	j := c.cfg.Journal
	sid := cand.Target.SessionID
	if c.cfg.Sessions == nil || sid == "" {
		// The engine blocks both cases (ADAPTER_UNAVAILABLE, NO_BOUND_SESSION) before
		// a candidate exists; defensive.
		_ = j.Transition(cand.IdempotencyKey, journal.Aborted, map[string]any{"reason": "no session adapter or no bound session"}, 0)
		return journal.Aborted
	}
	if err := j.Transition(cand.IdempotencyKey, journal.Executing, map[string]any{"session_id": sid}, 0); err != nil {
		log.Error("action.journal", "err", err)
		return journal.Unknown
	}
	reason := revokeReason(res, d)
	start := time.Now()
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	claimed, callErr := c.cfg.Sessions.Revoke(callCtx, sid, reason, res.Event.ID, cand.IdempotencyKey)
	cancel()
	latency := float64(time.Since(start).Microseconds()) / 1000

	state, detail := c.verifySession(ctx, sid, claimed, callErr)
	detail["adapter"] = c.cfg.Sessions.Name()
	detail["reason_sent"] = reason
	_ = j.Transition(cand.IdempotencyKey, state, detail, latency)
	log.Info("action.done", "state", state, "session", sid, "latency_ms", latency, "detail", detail)
	return state
}

// revokeReason is the text sent to the gateway: the profile, the engine's findings
// and the evidence, so the gateway's own log says why the run was cut off.
func revokeReason(res normalize.Result, d policy.Decision) string {
	codes := ""
	for i, f := range d.Findings {
		if i > 0 {
			codes += ","
		}
		codes += f.Code
	}
	if codes == "" {
		codes = string(d.Status)
	}
	return truncate(fmt.Sprintf("river3 %s: %s on %s (event %s)", res.Context.ProfileName, codes, res.Workload.AssetID, res.Event.ID), 512)
}

// verifySession settles a revoke from the gateway's inspected state, never from the
// revoke call's reply: revoked → VERIFIED; active or ended → FAILED (ended is not
// what we did, and the gateway may let an ended id be re-bound); unknown → UNKNOWN
// (the gateway no longer knows the session; nothing proves it was cut off by us).
// An inspection error is UNKNOWN too. The reply to the revoke call and any error are
// kept as evidence alongside.
func (c *Controller) verifySession(ctx context.Context, sid string, claimed adapter.SessionState, callErr error) (journal.State, map[string]any) {
	detail := map[string]any{"session_id": sid}
	if callErr != nil {
		detail["adapter_error"] = callErr.Error()
	}
	if claimed != "" {
		detail["gateway_reply"] = string(claimed)
	}
	inspectCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	info, err := c.cfg.Sessions.InspectSession(inspectCtx, sid)
	cancel()
	if err != nil {
		detail["inspect_error"] = err.Error()
		detail["session_state"] = string(adapter.SessionUnknown)
		return journal.Unknown, detail
	}
	detail["session_state"] = string(info.State)
	if info.Principal != "" {
		detail["principal"] = info.Principal
	}
	switch info.State {
	case adapter.SessionRevoked:
		return journal.Verified, detail
	case adapter.SessionUnknown:
		detail["reason"] = "gateway does not know the session after the revoke; outcome not established"
		return journal.Unknown, detail
	}
	detail["reason"] = fmt.Sprintf("gateway reports the session %s, wanted revoked", info.State)
	return journal.Failed, detail
}

// verify inspects the runtime and decides VERIFIED / FAILED / UNKNOWN from what it
// sees, never from the adapter call's return value.
//
// Status Unknown from the adapter means the runtime answered with a state this
// controller has no name for (podman "pausing"/"stopping", an OpenShell sandbox mid
// transition). That is not evidence the action failed, and it is not evidence it
// worked, so it is journaled UNKNOWN (reported as workload_state "unknown") rather
// than FAILED. Missing is different: the runtime positively says the container is
// gone, which for a pause is a failure.
func (c *Controller) verify(ctx context.Context, containerID, generation string, want adapter.Status, callErr error) (journal.State, map[string]any) {
	detail := map[string]any{}
	if callErr != nil {
		detail["adapter_error"] = callErr.Error()
	}
	inspectCtx, cancel := context.WithTimeout(ctx, c.cfg.ActionTimeout)
	info, err := c.cfg.Adapter.Inspect(inspectCtx, containerID)
	cancel()
	if err != nil {
		detail["inspect_error"] = err.Error()
		return journal.Unknown, detail
	}
	observed := map[string]any{"status": string(info.Status), "container_id": short(info.ContainerID), "generation": info.Generation}
	if info.Note != "" {
		observed["note"] = info.Note // e.g. openshell: the generation is configuration, not an observation
	}
	detail["observed"] = observed
	switch {
	case want == adapter.Exited && (info.Status == adapter.Exited || info.Status == adapter.Missing):
		return journal.Verified, detail
	case info.ContainerID != containerID || (generation != "" && info.Generation != generation):
		detail["reason"] = "runtime shows a different container or generation"
		return journal.Failed, detail
	case info.Status == want:
		return journal.Verified, detail
	case info.Status == adapter.Unknown:
		detail["reason"] = fmt.Sprintf("runtime reported a transitional or unrecognised state, wanted %s; outcome not established", want)
		return journal.Unknown, detail
	}
	detail["reason"] = fmt.Sprintf("runtime is %s, wanted %s", info.Status, want)
	return journal.Failed, detail
}

// reconcile settles an action left RESERVED or EXECUTING by a previous process.
func (c *Controller) reconcile(ctx context.Context, a journal.ActionView) {
	j := c.cfg.Journal
	if a.State == journal.Reserved {
		// The adapter was never called (the key is written before the call).
		_ = j.Transition(a.Key, journal.Aborted, map[string]any{"reason": "controller restarted before execution", "reconciled": true}, 0)
		c.cfg.Log.Warn("reconcile.aborted", "key", a.Key[:19])
		return
	}
	if a.Action == string(policy.Revoke) {
		// The session id was journaled with the EXECUTING transition. Settle by asking
		// the gateway; without an adapter or an id nothing can be established.
		sid, _ := a.Detail["session_id"].(string)
		var state journal.State
		var detail map[string]any
		if c.cfg.Sessions == nil || sid == "" {
			state, detail = journal.Unknown, map[string]any{"reason": "controller restarted mid-revoke; no session adapter or session id to inspect"}
		} else {
			state, detail = c.verifySession(ctx, sid, "", nil)
			detail["adapter"] = c.cfg.Sessions.Name()
		}
		detail["reconciled"] = true
		_ = j.Transition(a.Key, state, detail, 0)
		c.cfg.Log.Warn("reconcile.settled", "key", a.Key[:19], "state", state, "session", sid)
		return
	}
	want := adapter.Paused
	state, detail := c.verify(ctx, a.Target, "", want, nil)
	detail["reconciled"] = true
	detail["adapter"] = c.cfg.Adapter.Name()
	_ = j.Transition(a.Key, state, detail, 0)
	c.cfg.Log.Warn("reconcile.settled", "key", a.Key[:19], "state", state)
}

// ------------------------------------------------------------------ helpers

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func joinNotes(n []string) string {
	out := ""
	for i, s := range n {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out + "."
}

func decodeStored(raw json.RawMessage) (stored, error) {
	var s stored
	err := json.Unmarshal(raw, &s)
	return s, err
}
