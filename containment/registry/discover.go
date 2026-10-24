package registry

import (
	"fmt"
	"sort"
	"strings"

	policy "river3.local/policy"
)

// Runtime discovery (CONTRACTS.md §4): workloads are built from containers that
// opted in with labels instead of from the enrollment file's "workloads" list.
//
// Trust boundary. A label is written by whoever started the container, which on a
// node this controller protects is the platform team, not the agent inside the
// container: a process cannot relabel its own container. Labels therefore carry the
// same weight the registry file did (administrator statements), with the same
// validation. What a label can NOT do is set anything the runtime itself reports:
// the container id and the generation (StartedAt) are read from the runtime's own
// inspect response, by the same adapter the controller later verifies with, so an
// enrolled generation always equals what Inspect returns for a container that has
// not restarted. Sensors (token hashes, capabilities) never come from labels; they
// stay in the file, because a token hash on a container label would be readable by
// anyone who can list containers.

// Labels a container uses to enrol. Values per CONTRACTS.md §4.1.
const (
	LabelEnroll    = "river3.enroll"
	LabelAssetID   = "river3.asset_id"
	LabelProfile   = "river3.profile"
	LabelKind      = "river3.kind"
	LabelName      = "river3.name"
	LabelDedicated = "river3.dedicated"
	LabelActions   = "river3.actions"
	LabelTeam      = "river3.team"
)

// Container is one running container as the runtime lists it. Generation is the
// runtime's restart marker exactly as the adapter's Inspect reports it.
type Container struct {
	ID         string
	Name       string
	Labels     map[string]string
	Generation string
}

// Skipped explains why a labelled container was not enrolled. Every skip is an
// administrator mistake on that container's labels, so it is reported, not hidden,
// but it never prevents the other containers from being enrolled.
type Skipped struct {
	ContainerID string
	Reason      string
}

// WorkloadFromLabels builds the enrollment one container asks for. It applies the
// contract's defaults (name, dedicated, actions) and returns an error for anything
// the registry rules would refuse, so the caller can skip that container alone.
func WorkloadFromLabels(c Container) (Workload, error) {
	l := c.Labels
	if l[LabelEnroll] != "true" {
		return Workload{}, fmt.Errorf("%s is not \"true\"", LabelEnroll)
	}
	if !fullContainer.MatchString(c.ID) {
		return Workload{}, fmt.Errorf("runtime returned a non-full container id %q", c.ID)
	}
	if !identifier.MatchString(c.Generation) {
		// A container that never started has StartedAt 0001-01-01T00:00:00Z in Docker
		// and "" in Podman; neither is a generation the controller can verify against.
		return Workload{}, fmt.Errorf("runtime reports no usable start time (%q)", c.Generation)
	}
	w := Workload{
		AssetID:     l[LabelAssetID],
		Profile:     l[LabelProfile],
		Kind:        l[LabelKind],
		Name:        l[LabelName],
		Team:        l[LabelTeam],
		ContainerID: c.ID,
		Generation:  c.Generation,
		Active:      true,
	}
	if !identifier.MatchString(w.AssetID) {
		return Workload{}, fmt.Errorf("%s %q is not a valid identifier", LabelAssetID, w.AssetID)
	}
	if w.Profile == "" {
		return Workload{}, fmt.Errorf("%s is required", LabelProfile)
	}
	if w.Kind != "ai_worker" && w.Kind != "shared_service" {
		return Workload{}, fmt.Errorf("%s must be ai_worker or shared_service, got %q", LabelKind, w.Kind)
	}
	if w.Name == "" {
		w.Name = strings.TrimPrefix(c.Name, "/")
	}
	if w.Name == "" {
		w.Name = w.AssetID
	}
	switch v, set := l[LabelDedicated]; {
	case !set:
		w.Dedicated = w.Kind == "ai_worker"
	case v == "true":
		w.Dedicated = true
	case v == "false":
		w.Dedicated = false
	default:
		return Workload{}, fmt.Errorf("%s must be true or false, got %q", LabelDedicated, v)
	}
	if v, set := l[LabelActions]; set {
		for _, a := range strings.Split(v, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			switch policy.Action(a) {
			case policy.Pause, policy.Revoke:
				w.PermittedActions = append(w.PermittedActions, policy.Action(a))
			default:
				return Workload{}, fmt.Errorf("%s: %q is not PAUSE_CONTAINER or REVOKE_SESSION", LabelActions, a)
			}
		}
	} else if w.Kind == "ai_worker" && w.Dedicated {
		w.PermittedActions = []policy.Action{policy.Pause}
	}
	if w.PermittedActions == nil {
		w.PermittedActions = []policy.Action{}
	}
	return w, nil
}

// Discover builds a registry from the file's node and sensors plus the labelled
// containers. profileKnown, when set, drops a container bound to a profile the
// engine does not have: enrolling it would make every event from it an error and
// would block policy sync (BuildPolicy refuses a set that leaves an enrolled
// workload without its profile), so a typo on one container must not take the
// node's policy updates hostage. The file's own workloads are ignored: with
// discovery on, the runtime is the source of truth for what is enrolled.
//
// Two containers claiming the same asset id are both skipped: the controller cannot
// know which one the administrator meant, and enrolling either would let a rogue
// container impersonate a legitimate asset by copying its labels.
func Discover(base File, containers []Container, profileKnown func(string) bool) (*Registry, []Skipped, error) {
	var skipped []Skipped
	byAsset := map[string][]Workload{}
	order := []string{}
	for _, c := range containers {
		w, err := WorkloadFromLabels(c)
		if err != nil {
			skipped = append(skipped, Skipped{ContainerID: c.ID, Reason: err.Error()})
			continue
		}
		if profileKnown != nil && !profileKnown(w.Profile) {
			skipped = append(skipped, Skipped{ContainerID: c.ID, Reason: fmt.Sprintf("profile %q is not in the active policy set", w.Profile)})
			continue
		}
		if _, seen := byAsset[w.AssetID]; !seen {
			order = append(order, w.AssetID)
		}
		byAsset[w.AssetID] = append(byAsset[w.AssetID], w)
	}
	file := File{Node: base.Node, Sensors: base.Sensors}
	for _, id := range order {
		ws := byAsset[id]
		if len(ws) > 1 {
			for _, w := range ws {
				skipped = append(skipped, Skipped{ContainerID: w.ContainerID, Reason: fmt.Sprintf("asset id %q is claimed by %d containers", id, len(ws))})
			}
			continue
		}
		file.Workloads = append(file.Workloads, ws[0])
	}
	sort.Slice(file.Workloads, func(i, k int) bool { return file.Workloads[i].AssetID < file.Workloads[k].AssetID })
	r, err := New(file)
	if err != nil {
		// Per-container checks above mirror New's, so this is a rule the two disagree on
		// (or a bad node/sensor section). Nothing is enrolled rather than guessing.
		return nil, skipped, err
	}
	return r, skipped, nil
}

// Fingerprint identifies a workload set by what matters for enrolment: asset,
// container and generation. Equal fingerprints mean nothing changed worth logging
// or swapping; a differing one names the change.
func Fingerprint(r *Registry) string {
	ws := r.Workloads()
	sort.Slice(ws, func(i, k int) bool { return ws[i].AssetID < ws[k].AssetID })
	var b strings.Builder
	for _, w := range ws {
		b.WriteString(w.AssetID)
		b.WriteByte('=')
		b.WriteString(w.ContainerID)
		b.WriteByte('@')
		b.WriteString(w.Generation)
		b.WriteByte(';')
	}
	return b.String()
}

// Diff summarises how next differs from prev, for the one log line per change.
type Diff struct {
	Added, Removed, Restarted []string // asset ids
}

func DiffRegistries(prev, next *Registry) Diff {
	d := Diff{Added: []string{}, Removed: []string{}, Restarted: []string{}} // empty, not null, in the log line
	old := map[string]Workload{}
	if prev != nil {
		for _, w := range prev.Workloads() {
			old[w.AssetID] = w
		}
	}
	for _, w := range next.Workloads() {
		o, ok := old[w.AssetID]
		switch {
		case !ok:
			d.Added = append(d.Added, w.AssetID)
		case o.ContainerID != w.ContainerID || o.Generation != w.Generation:
			d.Restarted = append(d.Restarted, w.AssetID)
		}
		delete(old, w.AssetID)
	}
	for id := range old {
		d.Removed = append(d.Removed, id)
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Restarted)
	return d
}

func (d Diff) Empty() bool { return len(d.Added)+len(d.Removed)+len(d.Restarted) == 0 }
