package main

// Runtime discovery (contract §5, B3): enrol every running container that carries
// the river3.workload / river3.profile / river3.kind labels, through the
// Docker-compatible Engine API of docker or podman (-discover docker|podman).
//
// This is the operator-facing successor of -enroll-from-labels (§4.1,
// river3.enroll=true + river3.asset_id); both can run at once and share one merge.
// The trust model is the same: labels come from the runtime's database, never
// from inside the container; they claim an asset id and a profile, nothing more;
// identity is still the mount namespace the sensor resolves from the container id;
// and the -enroll file wins every conflict.
//
// Two triggers re-list containers: the periodic -refresh, and the runtime's own
// event stream (GET /events, container start/die/stop/pause/unpause), which asks
// the enroller for an immediate refresh. The stream is best effort: when it is
// unavailable the periodic refresh alone keeps the set current.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	labelWorkload = "river3.workload" // asset id (identifier)
	// river3.profile and river3.kind are shared with -enroll-from-labels (labelProfile,
	// labelKind); river3.name and river3.team stay optional here too.
)

// discoverer lists labelled containers and remembers which ids it has already
// complained about, so a container with bad labels is logged once, not every -refresh.
type discoverer struct {
	rt   ContainerRuntime
	kind string // "docker" | "podman": stamped on each Enrollment and sent to the API

	mu       sync.Mutex
	reported map[string]string // container id → last problem reported
}

func newDiscoverer(rt ContainerRuntime, kind string) *discoverer {
	return &discoverer{rt: rt, kind: kind, reported: map[string]string{}}
}

// enrollmentFromWorkloadLabels validates the §5 labels on one container with the
// -enroll file's rules, so a label can never produce an enrollment the file could not.
func enrollmentFromWorkloadLabels(c containerSummary) (Enrollment, error) {
	l := c.Labels
	en := Enrollment{
		AssetID: l[labelWorkload], Profile: l[labelProfile], Kind: l[labelKind], Name: l[labelName],
		Team: l[labelTeam], ContainerID: c.ID,
	}
	if !identRe.MatchString(en.AssetID) {
		return Enrollment{}, errors.New(labelWorkload + " missing or not an identifier")
	}
	if !identRe.MatchString(en.Profile) {
		return Enrollment{}, errors.New(labelProfile + " missing or not an identifier")
	}
	if en.Kind != "ai_worker" && en.Kind != "shared_service" {
		return Enrollment{}, errors.New(labelKind + " must be ai_worker or shared_service")
	}
	if len(en.Team) > 64 {
		return Enrollment{}, errors.New(labelTeam + " longer than 64")
	}
	if !fullCIDRe.MatchString(c.ID) {
		return Enrollment{}, errors.New("container id is not the full 64-hex id")
	}
	if en.Name == "" {
		for _, n := range c.Names {
			if n = strings.TrimPrefix(n, "/"); n != "" {
				en.Name = n
				break
			}
		}
	}
	if en.Name == "" {
		en.Name = en.AssetID
	}
	return en, nil
}

// Discover is the Enroller.Discover function: list, validate, report new problems.
// A container that keeps the same bad labels is reported once; a fixed or vanished
// container is forgotten so a later regression is reported again.
func (d *discoverer) Discover(ctx context.Context) ([]Enrollment, []string, error) {
	list, err := d.rt.ListLabelled(ctx, labelWorkload)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	if len(list) > maxEnrolled {
		// The merge caps the total anyway; cutting here bounds the inspect calls too.
		list = list[:maxEnrolled]
	}
	out := make([]Enrollment, 0, len(list))
	var problems []string
	current := map[string]string{}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range list {
		en, err := enrollmentFromWorkloadLabels(c)
		if err != nil {
			msg := fmt.Sprintf("container %s: %v (skipped)", shortID(c.ID), err)
			current[c.ID] = msg
			if d.reported[c.ID] != msg {
				problems = append(problems, msg)
			}
			continue
		}
		en.Discovered = d.kind
		out = append(out, en)
	}
	d.reported = current
	return out, problems, nil
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// combineDiscovery runs several discovery sources and merges them in order: an
// asset id or container id claimed by an earlier source keeps it (so
// -enroll-from-labels, listed first, beats -discover for the same container).
func combineDiscovery(sources ...func(context.Context) ([]Enrollment, []string, error)) func(context.Context) ([]Enrollment, []string, error) {
	if len(sources) == 1 {
		return sources[0]
	}
	return func(ctx context.Context) ([]Enrollment, []string, error) {
		var all []Enrollment
		var problems []string
		for _, src := range sources {
			found, probs, err := src(ctx)
			if err != nil {
				return nil, nil, err
			}
			problems = append(problems, probs...)
			merged, conflicts := mergeEnrollments(all, found)
			all = merged
			problems = append(problems, conflicts...)
		}
		return all, problems, nil
	}
}
