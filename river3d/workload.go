package main

// Enrollment: which containers the sensor watches, and how a kernel identity
// (mount-namespace inode) maps back to a workload the operator enrolled.
//
// The workload never chooses its own identity. The sensor resolves a container id
// the operator wrote down to a PID through the container runtime, reads that PID's
// mount namespace from /proc, and only then adds the inode to the BPF `watched`
// map. Everything else in the container is just syscalls from that namespace.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Enrollment is one entry of the -enroll file.
type Enrollment struct {
	AssetID     string `json:"asset_id"`
	Name        string `json:"name"`
	Profile     string `json:"profile"`
	Kind        string `json:"kind"`                   // ai_worker | shared_service
	ContainerID string `json:"container_id,omitempty"` // full 64-hex id; resolved to a PID via the runtime
	PID         uint32 `json:"pid,omitempty"`          // lab shortcut: watch this process's mount namespace
	Mntns       uint32 `json:"mntns,omitempty"`        // lab shortcut: watch this mount-ns inode directly
	Team        string `json:"team,omitempty"`         // forwarded to the API for team scoping; not an identity input
	// Discovered is "docker" or "podman" when the enrollment came from -discover
	// labels (discover.go), "" for the file and -enroll-from-labels. Never read from
	// the file; sent to the API as labels.discovered on registration.
	Discovered string `json:"-"`
}

var (
	identRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	fullCIDRe   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	mntLinkRe   = regexp.MustCompile(`^mnt:\[(\d+)\]$`)
	maxEnrolled = 1024
)

func loadEnrollments(path string) ([]Enrollment, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var list []Enrollment
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(list) == 0 || len(list) > maxEnrolled {
		return nil, fmt.Errorf("%s: need 1..%d enrollments", path, maxEnrolled)
	}
	seen := map[string]bool{}
	for i, e := range list {
		if !identRe.MatchString(e.AssetID) || e.Name == "" || e.Profile == "" {
			return nil, fmt.Errorf("%s[%d]: asset_id, name and profile are required", path, i)
		}
		if e.Kind != "ai_worker" && e.Kind != "shared_service" {
			return nil, fmt.Errorf("%s[%d]: kind must be ai_worker or shared_service", path, i)
		}
		if e.ContainerID != "" && !fullCIDRe.MatchString(e.ContainerID) {
			return nil, fmt.Errorf("%s[%d]: container_id must be the full 64-hex id", path, i)
		}
		if e.ContainerID == "" && e.PID == 0 && e.Mntns == 0 {
			return nil, fmt.Errorf("%s[%d]: one of container_id, pid or mntns is required", path, i)
		}
		if len(e.Team) > 64 {
			return nil, fmt.Errorf("%s[%d]: team longer than 64", path, i)
		}
		if seen[e.AssetID] {
			return nil, fmt.Errorf("%s[%d]: duplicate asset_id %q", path, i, e.AssetID)
		}
		seen[e.AssetID] = true
	}
	return list, nil
}

// mntnsOf reads the mount-namespace inode of a process from /proc.
func mntnsOf(pid uint32) (uint32, error) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return 0, err
	}
	m := mntLinkRe.FindStringSubmatch(link)
	if m == nil {
		return 0, fmt.Errorf("unexpected ns link %q", link)
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// RuntimeResolver finds the init PID of a container. Only the full id is accepted.
type RuntimeResolver interface {
	PID(ctx context.Context, containerID string) (uint32, error)
}

// The docker / podman implementation lives in runtime.go.

var errNotRunning = errors.New("container is not running")

// Watchlist is the userspace mirror of the BPF `watched` map: mntns → workload.
type Watchlist struct {
	mu    sync.RWMutex
	byNS  map[uint32]WorkloadRef
	byCID map[string]WorkloadRef // for the Falco source, which reports container ids
}

func newWatchlist() *Watchlist {
	return &Watchlist{byNS: map[uint32]WorkloadRef{}, byCID: map[string]WorkloadRef{}}
}

func (w *Watchlist) Lookup(mntns uint32) (WorkloadRef, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	ref, ok := w.byNS[mntns]
	return ref, ok
}

// LookupContainer resolves a full or prefix (>= 12 chars) container id.
func (w *Watchlist) LookupContainer(id string) (WorkloadRef, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if ref, ok := w.byCID[id]; ok {
		return ref, true
	}
	if len(id) < 12 {
		return WorkloadRef{}, false
	}
	var found WorkloadRef
	n := 0
	for cid, ref := range w.byCID {
		if strings.HasPrefix(cid, id) {
			found, n = ref, n+1
		}
	}
	if n != 1 {
		return WorkloadRef{}, false
	}
	return found, true
}

// Snapshot returns the current mntns set, for diffing against the BPF map.
func (w *Watchlist) Snapshot() map[uint32]WorkloadRef {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[uint32]WorkloadRef, len(w.byNS))
	for k, v := range w.byNS {
		out[k] = v
	}
	return out
}

func (w *Watchlist) replace(byNS map[uint32]WorkloadRef, byCID map[string]WorkloadRef) {
	w.mu.Lock()
	w.byNS, w.byCID = byNS, byCID
	w.mu.Unlock()
}

// Enroller resolves enrollments to mount namespaces and keeps the kernel map in sync.
type Enroller struct {
	// Enrollments is the -enroll file (may be empty when discovery is on).
	Enrollments []Enrollment
	// Discover, when set, returns the enrollments found through runtime labels
	// (-enroll-from-labels). It is called on every refresh; a failure keeps the
	// previous discovery result so a hiccup on the runtime socket does not unwatch
	// every container.
	Discover func(ctx context.Context) ([]Enrollment, []string, error)
	// Runtime resolves container ids to PIDs. nil means identity by container id
	// only (the Falco source): nothing is resolved and nothing is logged about it.
	Runtime RuntimeResolver
	Watch   *Watchlist
	// SetWatched applies the desired mntns set to the kernel map (nil for the Falco source).
	SetWatched func(desired map[uint32]bool) error
	Log        func(format string, args ...any)
	// Images, when set, gets mntns → init pid after every refresh so it can keep a
	// per-workload table of image binaries (binident.go). nil for the Falco source.
	Images *imageIndex
	// Inodes, when set, is refreshed synchronously with the watched set so inline
	// blocking is in force the moment a workload is watched (-block-decoys).
	Inodes *inodeBlocker
	// OnEnrolled is called the first time an asset id is seen, and again when its
	// descriptive fields change (API registration). Called outside any lock.
	OnEnrolled func(Enrollment)

	lastDiscovered []Enrollment
	registered     map[string]Enrollment

	kickOnce sync.Once
	kick     chan struct{}
}

// Kick asks Run for an immediate refresh (the runtime's event stream saw a
// container start or stop). Non-blocking; a burst of events coalesces into one
// refresh, and the periodic refresh continues regardless.
func (e *Enroller) Kick() {
	e.kickOnce.Do(func() { e.kick = make(chan struct{}, 1) })
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Active returns the merged enrollment list the last refresh worked from.
func (e *Enroller) Active(ctx context.Context) []Enrollment {
	if e.Discover == nil {
		return e.Enrollments
	}
	found, problems, err := e.Discover(ctx)
	if err != nil {
		e.Log("enroll: discovery: %v (keeping the previous %d label enrollment(s))", err, len(e.lastDiscovered))
		found = e.lastDiscovered
	} else {
		e.lastDiscovered = found
		for _, p := range problems {
			e.Log("enroll: discovery: %s", p)
		}
	}
	merged, conflicts := mergeEnrollments(e.Enrollments, found)
	for _, c := range conflicts {
		e.Log("enroll: %s", c)
	}
	return merged
}

// Refresh re-resolves every enrollment. A container that restarted gets a new PID
// and a new mount namespace; the old inode is dropped and the new one watched.
func (e *Enroller) Refresh(ctx context.Context) error {
	byNS := map[uint32]WorkloadRef{}
	byCID := map[string]WorkloadRef{}
	pids := map[uint32]uint32{}       // mntns → a pid inside it, for the image walk
	procs := map[uint32]watchedProc{} // mntns → pid + profile, for inline blocking
	var problems []string
	active := e.Active(ctx)
	var fresh []Enrollment
	for _, en := range active {
		if prev, ok := e.registered[en.AssetID]; !ok || prev != en {
			fresh = append(fresh, en)
		}
	}
	for _, en := range active {
		ref := WorkloadRef{ID: en.AssetID, Name: en.Name, Profile: en.Profile, Kind: en.Kind, Enrolled: true, ContainerID: en.ContainerID, Team: en.Team}
		if en.ContainerID != "" {
			byCID[en.ContainerID] = ref
		}
		ns := en.Mntns
		pid := en.PID
		if ns == 0 && pid == 0 && en.ContainerID != "" {
			if e.Runtime == nil {
				continue // Falco source: the container id is the identity, no PID needed
			}
			p, err := e.Runtime.PID(ctx, en.ContainerID)
			if err != nil {
				problems = append(problems, en.AssetID+": "+err.Error())
				continue
			}
			pid = p
		}
		if ns == 0 && pid != 0 {
			n, err := mntnsOf(pid)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: pid %d: %v", en.AssetID, pid, err))
				continue
			}
			ns = n
		}
		if ns == 0 {
			continue
		}
		if other, dup := byNS[ns]; dup {
			problems = append(problems, fmt.Sprintf("%s and %s share mount namespace %d; neither is watched", other.ID, en.AssetID, ns))
			delete(byNS, ns)
			delete(pids, ns)
			delete(procs, ns)
			continue
		}
		byNS[ns] = ref
		if pid != 0 {
			pids[ns] = pid // a bare mntns enrollment has no root to walk: its execs stay NAME_ONLY
		}
		procs[ns] = watchedProc{PID: pid, Profile: en.Profile, Asset: en.AssetID}
	}
	e.Watch.replace(byNS, byCID)
	if e.Images != nil {
		e.Images.refresh(ctx, pids)
	}
	if e.Inodes != nil {
		// Before the namespace is watched, so no window exists in which a decoy
		// open in a freshly enrolled workload is observed but not denied.
		if err := e.Inodes.refresh(ctx, procs); err != nil {
			return fmt.Errorf("block-decoys: %w", err)
		}
	}
	if e.SetWatched != nil {
		desired := make(map[uint32]bool, len(byNS))
		for ns := range byNS {
			desired[ns] = true
		}
		if err := e.SetWatched(desired); err != nil {
			return err
		}
	}
	for _, p := range problems {
		e.Log("enroll: %s", p)
	}
	if e.registered == nil {
		e.registered = map[string]Enrollment{}
	}
	for _, en := range fresh {
		e.registered[en.AssetID] = en
		if e.OnEnrolled != nil {
			e.OnEnrolled(en)
		}
	}
	return nil
}

// Run refreshes on an interval, and on Kick, until ctx ends. Kicked refreshes are
// spaced at least 250 ms apart so a storm of runtime events cannot turn into a
// storm of listings; the periodic tick is never skipped.
func (e *Enroller) Run(ctx context.Context, every time.Duration) {
	e.kickOnce.Do(func() { e.kick = make(chan struct{}, 1) })
	t := time.NewTicker(every)
	defer t.Stop()
	refresh := func() {
		if err := e.Refresh(ctx); err != nil {
			e.Log("enroll: refresh: %v", err)
		}
	}
	const minKickSpacing = 250 * time.Millisecond
	var lastKick time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		case <-e.kick:
			if wait := minKickSpacing - time.Since(lastKick); wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			lastKick = time.Now()
			refresh()
		}
	}
}

// registerWorkload tells the API about one enrollment (POST /api/v1/workloads).
// The sensor token holds workloads.write. Failures are logged, not fatal: events for
// an unregistered workload are rejected by the API with 422 and retried later.
// `team` is sent only when set (contract §4.3); a discovered workload carries
// `labels: {"discovered": "docker"|"podman"}` (WorkloadIn.labels, ≤32 entries).
func registerWorkload(ctx context.Context, api *apiClient, en Enrollment) {
	if err := api.post(ctx, "/api/v1/workloads", workloadRegistration(en)); err != nil {
		logf("api: register workload %s: %v", en.AssetID, err)
	}
}

func workloadRegistration(en Enrollment) map[string]any {
	body := map[string]any{"id": en.AssetID, "name": en.Name, "profile": en.Profile, "kind": en.Kind, "sensor": "ebpf"}
	if en.Team != "" {
		body["team"] = en.Team
	}
	if en.Discovered != "" {
		body["labels"] = map[string]string{"discovered": en.Discovered}
	}
	return body
}
