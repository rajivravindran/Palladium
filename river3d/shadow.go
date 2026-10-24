package main

// Optional in-process evaluation (-shadow-profiles DIR): run the policy engine on
// every event right here and log the decision. This is the sensor's own view for
// development — it is shadow-only and carries no trusted context, exactly like
// policy-eval, so it can never produce a candidate. Real evaluation with identity,
// resource verification and containment happens in river3-containd, which is where
// the "controller" sink delivers.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	policy "river3.local/policy"
)

type shadowEval struct {
	engine   *policy.Engine
	profiles map[string]*policy.Profile
	out      io.Writer
}

func newShadowEval(dir string, out io.Writer) (*shadowEval, error) {
	loaded, err := policy.LoadProfiles(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(loaded))
	for n := range loaded {
		names = append(names, n)
	}
	sort.Strings(names)
	list := make([]policy.Profile, 0, len(names))
	for _, n := range names {
		p := *loaded[n]
		p.Mode = policy.Shadow // never anything else in-process
		list = append(list, p)
	}
	eng, err := policy.NewEngine(list, policy.Options{})
	if err != nil {
		return nil, err
	}
	return &shadowEval{engine: eng, profiles: loaded, out: out}, nil
}

// toPolicyEvent is the sensor-side mapping; the controller's normalizer does the
// same with trusted context and is authoritative.
func toPolicyEvent(ev Event, tenant, host string) (policy.Event, error) {
	f := ev.Facts
	pe := policy.Event{
		ID: f.ID, Provenance: policy.Live,
		Identity:   policy.Identity{TenantID: tenant, AssetID: f.Workload.ID, HostID: host, Generation: "sensor", ContainerID: f.Workload.ContainerID},
		ObservedAt: time.Unix(0, int64(f.Received)).UTC(),
	}
	switch f.Outcome {
	case OutcomeSuccess:
		pe.Outcome = policy.Succeeded
	case OutcomeFailed, OutcomeBlocked: // blocked inline by the sensor: failed-class (contract §9)
		pe.Outcome = policy.Failed
	case OutcomePending:
		pe.Outcome = policy.Attempted
	default:
		pe.Outcome = policy.UnknownOutcome
	}
	switch f.Kind {
	case KindFileOpen:
		pe.Operation = policy.FileOpen
		pe.Path = f.Target.Path
		pe.OpenRead = f.Target.Access == "read" || f.Target.Access == "rw"
		pe.OpenWrite = f.Target.Access == "write" || f.Target.Access == "rw"
	case KindProcessExec:
		pe.Operation = policy.ProcessExec
		pe.BinaryClass = f.Target.BinaryClass
	case KindNetConnect:
		pe.Operation = policy.NetConnect
		pe.DestinationIP = f.Target.IP
		// Contract §4: the port, and the hostname the sensor resolved for the IP (""
		// when unknown; hostname-only rules then stay out of scope, host_unknown).
		pe.Port = f.Target.Port
		pe.DestHost = f.Target.Host
	default:
		return pe, fmt.Errorf("unsupported kind %q", f.Kind)
	}
	return pe, nil
}

func (s *shadowEval) Emit(ev Event) {
	p, ok := s.profiles[ev.Facts.Workload.Profile]
	if !ok {
		return
	}
	pe, err := toPolicyEvent(ev, "sensor-local", "sensor-local")
	if err != nil {
		return
	}
	d, err := s.engine.Evaluate(pe, policy.Context{ProfileName: p.Name, ProfileVersion: p.Version, Now: time.Now().UTC()})
	if err != nil {
		fmt.Fprintf(s.out, `{"shadow":"error","event":%q,"err":%q}`+"\n", ev.Facts.ID, err.Error())
		return
	}
	b, _ := json.Marshal(map[string]any{"shadow": d.Status, "event": ev.Facts.ID, "workload": ev.Facts.Workload.ID,
		"findings": d.Findings, "recommended": d.RecommendedAction, "blockers": d.Blockers})
	fmt.Fprintln(s.out, string(b))
}
