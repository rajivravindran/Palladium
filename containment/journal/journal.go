// Package journal is the controller's durable memory.
//
// It is an append-only JSONL file, fsync'd on every write, replayed at start-up.
// Nothing here is ever rewritten: a state change is a new record. That gives
//
//   - durable idempotency: a candidate's key is reserved before the adapter is
//     called, so a crash or a replayed event cannot pause twice;
//   - explicit outcome states for every attempted action
//     (RESERVED → ABORTED | EXECUTING → VERIFIED | FAILED | UNKNOWN);
//   - restart reconciliation: anything left EXECUTING is re-inspected, not assumed;
//   - an outbox: reports to the API are retried until acknowledged.
//
// A single file is deliberately simple for one node-local controller. It is not
// a shared store for several controllers acting on the same runtime.
package journal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

// State of an automatic action attempt.
type State string

const (
	Reserved  State = "RESERVED"  // key written; adapter not yet called
	Aborted   State = "ABORTED"   // revalidation refused; adapter never called
	Executing State = "EXECUTING" // adapter call in flight (or interrupted by a crash)
	Verified  State = "VERIFIED"  // runtime inspected and shows the intended state
	Failed    State = "FAILED"    // runtime inspected and does NOT show it
	Unknown   State = "UNKNOWN"   // runtime could not be inspected after the call
)

// Terminal reports whether no further transition is expected.
func (s State) Terminal() bool { return s == Aborted || s == Verified || s == Failed || s == Unknown }

// Record is one journal line. Kind selects which fields matter.
type Record struct {
	Seq  uint64    `json:"seq"`
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // decision | action | report | operator

	// decision: one engine decision for one event
	EventID    string          `json:"event_id,omitempty"`
	IncidentID string          `json:"incident_id,omitempty"` // set by a later report record
	Decision   json.RawMessage `json:"decision,omitempty"`
	Report     bool            `json:"report,omitempty"` // decision: this event is meant to reach the API

	// action: automatic containment keyed by the engine's idempotency key
	Key     string         `json:"key,omitempty"`
	State   State          `json:"state,omitempty"`
	Action  string         `json:"action,omitempty"`
	Target  string         `json:"target,omitempty"` // container id
	Asset   string         `json:"asset,omitempty"`
	Detail  map[string]any `json:"detail,omitempty"`
	Latency float64        `json:"latency_ms,omitempty"`

	// report: outbox progress for an event (incident created / response patched)
	Step string `json:"step,omitempty"` // incident_created | response_reported | orphaned
	Err  string `json:"err,omitempty"`

	// operator: handling of one operator request (resume / terminate) by action id
	ActionID string `json:"action_id,omitempty"`
	Result   string `json:"result,omitempty"` // handling | completed | failed | ignored | reported
}

// ActionView is the folded state of one automatic action.
type ActionView struct {
	Key       string
	State     State
	Action    string
	Target    string
	Asset     string
	EventID   string
	Detail    map[string]any
	Latency   float64
	UpdatedAt time.Time
	Reported  bool
}

// EventView is the folded state of one evaluated event.
type EventView struct {
	EventID       string
	IncidentID    string
	Decision      json.RawMessage
	Report        bool // false for IN_SCOPE (and unreported UNKNOWN): nothing is owed to the API
	Orphaned      bool // incident exists at the API but we never learned its id
	ResponseDone  bool
	HasResponse   bool // an action attached to this event reached a terminal state
	ActionKey     string
	UpdatedAt     time.Time
	CreateAttempt int
}

// OperatorView is the folded state of one operator request.
type OperatorView struct {
	ActionID string
	Result   string
	Detail   map[string]any
	Reported bool
}

// Journal is safe for concurrent use.
type Journal struct {
	mu    sync.Mutex
	f     *os.File
	seq   uint64
	acts  map[string]*ActionView
	evs   map[string]*EventView
	ops   map[string]*OperatorView
	order []string // event ids in first-seen order (for deterministic outbox scans)
}

// Open loads (replays) the journal at path, creating it if needed.
func Open(path string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	j := &Journal{f: f, acts: map[string]*ActionView{}, evs: map[string]*EventView{}, ops: map[string]*OperatorView{}}
	if err := j.replay(); err != nil {
		f.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Close() error { return j.f.Close() }

// maxRecord bounds one journal line. A record is a decision plus an incident body
// (≤ 2000-char reason, a handful of facts), far below this; anything larger is not
// something this process wrote.
const maxRecord = 4 * 1024 * 1024

// replay folds every complete record and repairs the tail.
//
// Every record this process writes is `<json>\n` in a single write, so a complete
// file ends in '\n'. A crash mid-write can leave a final chunk without the newline:
// either a complete JSON object (the bytes landed, the terminator did not) or a
// fragment. Both used to be left in place, and the next append then shared the line
// with the fragment, turning the next restart's "torn tail" into "corrupt record in
// the middle" and refusing the journal. So the tail is repaired here, before the
// file is appended to again: a complete unterminated record gets its newline, a
// fragment is truncated away. Garbage with complete records after it is still
// corruption and still refuses the journal: that was never a crash pattern.
func (j *Journal) replay() error {
	if _, err := j.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(j.f, 64*1024)
	var off int64 // byte offset of the start of the current chunk
	line := 0
	for {
		chunk, err := rd.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return err
		}
		terminated := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
		if len(chunk) > maxRecord {
			return fmt.Errorf("journal: record at line %d exceeds %d bytes", line+1, maxRecord)
		}
		if len(chunk) == 0 {
			break // clean EOF
		}
		line++
		body := chunk
		if terminated {
			body = chunk[:len(chunk)-1]
		}
		if len(body) > 0 {
			var r Record
			perr := json.Unmarshal(body, &r)
			switch {
			case perr != nil && !terminated:
				// Torn fragment at the very end: drop it so the next append starts a fresh line.
				if err := j.truncateTo(off); err != nil {
					return fmt.Errorf("journal: repairing torn tail: %w", err)
				}
				return j.seekEnd()
			case perr != nil:
				return fmt.Errorf("journal: corrupt record at line %d: %w", line, perr)
			}
			if r.Seq <= j.seq && j.seq != 0 {
				return fmt.Errorf("journal: sequence went backwards at line %d", line)
			}
			j.seq = r.Seq
			j.fold(r)
		}
		if !terminated {
			// Complete record (or stray whitespace) whose '\n' never landed: terminate it
			// so the next record is not written onto the same line.
			if _, err := j.f.Write([]byte{'\n'}); err != nil {
				return fmt.Errorf("journal: repairing unterminated tail: %w", err)
			}
			if err := j.f.Sync(); err != nil {
				return err
			}
			break
		}
		off += int64(len(chunk))
		if err == io.EOF {
			break
		}
	}
	return j.seekEnd()
}

// truncateTo cuts the file at off and makes it durable. ftruncate ignores O_APPEND,
// so this works on the same descriptor the journal appends through.
func (j *Journal) truncateTo(off int64) error {
	if err := j.f.Truncate(off); err != nil {
		return err
	}
	return j.f.Sync()
}

func (j *Journal) seekEnd() error {
	_, err := j.f.Seek(0, io.SeekEnd)
	return err
}

func (j *Journal) fold(r Record) {
	switch r.Kind {
	case "decision":
		ev := j.ev(r.EventID)
		ev.Decision = r.Decision
		ev.Report = r.Report
		ev.UpdatedAt = r.At
	case "action":
		a, ok := j.acts[r.Key]
		if !ok {
			a = &ActionView{Key: r.Key}
			j.acts[r.Key] = a
		}
		if r.State != "" {
			a.State = r.State
		}
		if r.Action != "" {
			a.Action = r.Action
		}
		if r.Target != "" {
			a.Target = r.Target
		}
		if r.Asset != "" {
			a.Asset = r.Asset
		}
		if r.EventID != "" {
			a.EventID = r.EventID
			ev := j.ev(r.EventID)
			ev.ActionKey = r.Key
			if a.State.Terminal() {
				ev.HasResponse = true // every terminal state, ABORTED included, is reported to the API
			}
		}
		if r.Detail != nil {
			a.Detail = r.Detail
		}
		if r.Latency > 0 {
			a.Latency = r.Latency
		}
		a.UpdatedAt = r.At
	case "report":
		ev := j.ev(r.EventID)
		switch r.Step {
		case "incident_created":
			ev.IncidentID = r.IncidentID
		case "incident_attempt":
			ev.CreateAttempt++
		case "orphaned":
			ev.Orphaned = true
		case "response_reported":
			ev.ResponseDone = true
			if a, ok := j.acts[ev.ActionKey]; ok {
				a.Reported = true
			}
		}
		ev.UpdatedAt = r.At
	case "operator":
		o, ok := j.ops[r.ActionID]
		if !ok {
			o = &OperatorView{ActionID: r.ActionID}
			j.ops[r.ActionID] = o
		}
		if r.Result == "reported" {
			o.Reported = true
		} else if r.Result != "" {
			o.Result = r.Result
		}
		if r.Detail != nil {
			o.Detail = r.Detail
		}
	}
}

func (j *Journal) ev(id string) *EventView {
	e, ok := j.evs[id]
	if !ok {
		e = &EventView{EventID: id}
		j.evs[id] = e
		j.order = append(j.order, id)
	}
	return e
}

// append writes one record durably and folds it into the in-memory view.
func (j *Journal) append(r Record) error {
	j.seq++
	r.Seq = j.seq
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := j.f.Sync(); err != nil {
		return err
	}
	j.fold(r)
	return nil
}

// ---------------------------------------------------------------- decisions

// RecordDecision stores an engine decision for an event. Returns false if the
// event was already evaluated (duplicate delivery).
func (j *Journal) RecordDecision(eventID string, decision any, report bool) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e, ok := j.evs[eventID]; ok && e.Decision != nil {
		return false, nil
	}
	raw, err := json.Marshal(decision)
	if err != nil {
		return false, err
	}
	return true, j.append(Record{Kind: "decision", EventID: eventID, Decision: raw, Report: report})
}

func (j *Journal) Event(eventID string) (EventView, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.evs[eventID]
	if !ok {
		return EventView{}, false
	}
	return *e, true
}

// ---------------------------------------------------------------- actions

var ErrDuplicate = errors.New("journal: idempotency key already reserved")

// Reserve durably claims an idempotency key before any adapter call. A second
// call with the same key returns ErrDuplicate and the existing view.
func (j *Journal) Reserve(key, action, target, asset, eventID string) (ActionView, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if a, ok := j.acts[key]; ok {
		return *a, ErrDuplicate
	}
	err := j.append(Record{Kind: "action", Key: key, State: Reserved, Action: action, Target: target, Asset: asset, EventID: eventID})
	return *j.acts[key], err
}

// Transition moves an action to a new state with optional detail.
func (j *Journal) Transition(key string, state State, detail map[string]any, latencyMS float64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	a, ok := j.acts[key]
	if !ok {
		return fmt.Errorf("journal: unknown action key")
	}
	if a.State.Terminal() {
		return fmt.Errorf("journal: action already %s", a.State)
	}
	return j.append(Record{Kind: "action", Key: key, State: state, Detail: detail, Latency: latencyMS, EventID: a.EventID})
}

func (j *Journal) Action(key string) (ActionView, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	a, ok := j.acts[key]
	if !ok {
		return ActionView{}, false
	}
	return *a, true
}

// InFlight returns actions left EXECUTING, e.g. after a crash. The controller
// must reconcile each against the runtime before doing anything else.
func (j *Journal) InFlight() []ActionView {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []ActionView
	for _, a := range j.acts {
		if a.State == Executing || a.State == Reserved {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].UpdatedAt.Before(out[k].UpdatedAt) })
	return out
}

// ---------------------------------------------------------------- outbox

func (j *Journal) MarkIncidentAttempt(eventID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.append(Record{Kind: "report", EventID: eventID, Step: "incident_attempt"})
}

func (j *Journal) MarkIncidentCreated(eventID, incidentID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.append(Record{Kind: "report", EventID: eventID, Step: "incident_created", IncidentID: incidentID})
}

func (j *Journal) MarkOrphaned(eventID, why string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.append(Record{Kind: "report", EventID: eventID, Step: "orphaned", Err: why})
}

func (j *Journal) MarkResponseReported(eventID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.append(Record{Kind: "report", EventID: eventID, Step: "response_reported"})
}

// Pending lists events whose reporting is incomplete, oldest first.
func (j *Journal) Pending() []EventView {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []EventView
	for _, id := range j.order {
		e := j.evs[id]
		if e.Decision == nil || e.Orphaned || !e.Report {
			continue
		}
		needIncident := e.IncidentID == ""
		needResponse := e.HasResponse && !e.ResponseDone
		if needIncident || needResponse {
			out = append(out, *e)
		}
	}
	return out
}

// ---------------------------------------------------------------- operator requests

// ClaimOperator records that this controller is handling an operator request.
// Returns false if it was already handled (duplicate webhook + poll delivery).
//
// request carries what the controller would need to settle the claim after a crash
// (workload, action, operator); it is journaled with the claim because the API's
// queue entry may be gone by the time the controller comes back.
func (j *Journal) ClaimOperator(actionID string, request map[string]any) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.ops[actionID]; ok {
		return false, nil
	}
	return true, j.append(Record{Kind: "operator", ActionID: actionID, Result: "handling", Detail: request})
}

// HandlingOperators lists operator requests claimed but never finished: the
// controller crashed (or was killed) between the claim and the result. Start
// settles each one before serving anything else.
func (j *Journal) HandlingOperators() []OperatorView {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []OperatorView
	for _, o := range j.ops {
		if o.Result == "handling" {
			out = append(out, *o)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ActionID < out[k].ActionID })
	return out
}

func (j *Journal) FinishOperator(actionID, result string, detail map[string]any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.append(Record{Kind: "operator", ActionID: actionID, Result: result, Detail: detail})
}

func (j *Journal) MarkOperatorReported(actionID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.append(Record{Kind: "operator", ActionID: actionID, Result: "reported"})
}

func (j *Journal) Operator(actionID string) (OperatorView, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	o, ok := j.ops[actionID]
	if !ok {
		return OperatorView{}, false
	}
	return *o, true
}

// UnreportedOperators lists finished operator requests whose result never reached the API.
func (j *Journal) UnreportedOperators() []OperatorView {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []OperatorView
	for _, o := range j.ops {
		if (o.Result == "completed" || o.Result == "failed") && !o.Reported {
			out = append(out, *o)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ActionID < out[k].ActionID })
	return out
}

// Stats is a small health summary.
type Stats struct {
	Events, Actions, Verified, Failed, Unknown, Aborted, InFlight, PendingReports, Orphaned int
}

func (j *Journal) Stats() Stats {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := Stats{Events: len(j.evs), Actions: len(j.acts)}
	for _, a := range j.acts {
		switch a.State {
		case Verified:
			s.Verified++
		case Failed:
			s.Failed++
		case Unknown:
			s.Unknown++
		case Aborted:
			s.Aborted++
		default:
			s.InFlight++
		}
	}
	for _, e := range j.evs {
		if e.Orphaned {
			s.Orphaned++
		} else if e.Decision != nil && e.Report && (e.IncidentID == "" || (e.HasResponse && !e.ResponseDone)) {
			s.PendingReports++
		}
	}
	return s
}
