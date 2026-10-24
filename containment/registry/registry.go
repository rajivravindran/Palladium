// Package registry is the controller's trusted enrollment store.
//
// Everything the policy engine's Context needs — tenant, host, asset, generation,
// container binding, permissions — comes from here, never from an event, a label
// or model text (policy/AGENTS.md). The file is administrator-managed, loaded
// strictly and atomically, and replaced as a whole snapshot.
package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	policy "river3.local/policy"
)

const maxFile = 1 << 20

var (
	identifier    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	fullContainer = regexp.MustCompile(`^[a-f0-9]{64}$`)
	hexSHA256     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Node identifies this controller's host. Tenant and host are node facts, so a
// sensor event can never claim a different tenant.
type Node struct {
	TenantID string `json:"tenant_id"`
	HostID   string `json:"host_id"`
}

// Sensor is an authenticated event source. ResolvesPaths is a trusted capability
// statement about the sensor build (kernel-side d_path), not something an event says.
type Sensor struct {
	Name          string `json:"name"`
	TokenSHA256   string `json:"token_sha256"`
	ResolvesPaths bool   `json:"resolves_paths"`
}

// Workload is one enrolled runtime unit bound to a profile.
type Workload struct {
	AssetID          string          `json:"asset_id"`
	Name             string          `json:"name"`
	Profile          string          `json:"profile"`
	Kind             string          `json:"kind"` // ai_worker | shared_service
	ContainerID      string          `json:"container_id"`
	Generation       string          `json:"generation"`
	SessionID        string          `json:"session_id,omitempty"`
	Dedicated        bool            `json:"dedicated"`
	Active           bool            `json:"active"`
	PermittedActions []policy.Action `json:"permitted_actions"`
	Team             string          `json:"team,omitempty"` // CONTRACTS.md §6; "" = unscoped
}

type File struct {
	Node      Node       `json:"node"`
	Sensors   []Sensor   `json:"sensors"`
	Workloads []Workload `json:"workloads"`
}

// Registry is an immutable, validated snapshot. Swap the whole value to update.
type Registry struct {
	node      Node
	sensors   map[string]Sensor // by token hash
	workloads map[string]Workload
	byCID     map[string]string // container id -> asset id
}

// Load reads and validates a registry file. Any problem rejects the whole file.
func Load(path string) (*Registry, error) {
	file, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	return New(file)
}

// LoadFile reads a registry file strictly without validating it; New does that.
// Runtime discovery uses it to keep the node and sensor sections while replacing
// the workloads with what the runtime reports.
func LoadFile(path string) (File, error) {
	var file File
	f, err := os.Open(path)
	if err != nil {
		return file, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return file, err
	}
	if len(data) > maxFile {
		return file, fmt.Errorf("registry: file too large")
	}
	if err := policy.DecodeStrict(data, &file); err != nil {
		return file, fmt.Errorf("registry: %w", err)
	}
	return file, nil
}

// New validates an in-memory registry file.
func New(file File) (*Registry, error) {
	if !identifier.MatchString(file.Node.TenantID) || !identifier.MatchString(file.Node.HostID) {
		return nil, fmt.Errorf("registry: node tenant_id and host_id are required identifiers")
	}
	r := &Registry{node: file.Node, sensors: map[string]Sensor{}, workloads: map[string]Workload{}, byCID: map[string]string{}}
	if len(file.Sensors) == 0 {
		return nil, fmt.Errorf("registry: at least one sensor is required")
	}
	if len(file.Sensors) > 64 || len(file.Workloads) > 1024 {
		return nil, fmt.Errorf("registry: too many sensors or workloads")
	}
	names := map[string]bool{}
	for _, s := range file.Sensors {
		if !identifier.MatchString(s.Name) || names[s.Name] {
			return nil, fmt.Errorf("registry: sensor name %q invalid or duplicated", s.Name)
		}
		names[s.Name] = true
		h := strings.ToLower(s.TokenSHA256)
		if !hexSHA256.MatchString(h) {
			return nil, fmt.Errorf("registry: sensor %q: token_sha256 must be 64 hex chars (plain tokens are never stored)", s.Name)
		}
		if _, dup := r.sensors[h]; dup {
			return nil, fmt.Errorf("registry: sensor %q shares a token with another sensor", s.Name)
		}
		s.TokenSHA256 = h
		r.sensors[h] = s
	}
	for _, w := range file.Workloads {
		if !identifier.MatchString(w.AssetID) {
			return nil, fmt.Errorf("registry: workload asset_id %q invalid", w.AssetID)
		}
		if _, dup := r.workloads[w.AssetID]; dup {
			return nil, fmt.Errorf("registry: workload %q duplicated", w.AssetID)
		}
		if w.Name == "" || w.Profile == "" {
			return nil, fmt.Errorf("registry: workload %q needs name and profile", w.AssetID)
		}
		if w.Kind != "ai_worker" && w.Kind != "shared_service" {
			return nil, fmt.Errorf("registry: workload %q: kind must be ai_worker or shared_service", w.AssetID)
		}
		if !fullContainer.MatchString(w.ContainerID) {
			return nil, fmt.Errorf("registry: workload %q: container_id must be the full 64-hex id", w.AssetID)
		}
		if !identifier.MatchString(w.Generation) {
			return nil, fmt.Errorf("registry: workload %q: generation is required", w.AssetID)
		}
		if w.SessionID != "" && !identifier.MatchString(w.SessionID) {
			return nil, fmt.Errorf("registry: workload %q: invalid session_id", w.AssetID)
		}
		if w.Kind == "shared_service" && w.Dedicated {
			return nil, fmt.Errorf("registry: workload %q: a shared service cannot be marked dedicated", w.AssetID)
		}
		if len(w.Team) > 64 {
			return nil, fmt.Errorf("registry: workload %q: team must be at most 64 characters", w.AssetID)
		}
		for _, a := range w.PermittedActions {
			if a != policy.Pause && a != policy.Revoke {
				return nil, fmt.Errorf("registry: workload %q: permitted_actions may only contain PAUSE_CONTAINER or REVOKE_SESSION", w.AssetID)
			}
			if a == policy.Pause && w.Kind != "ai_worker" {
				return nil, fmt.Errorf("registry: workload %q: PAUSE_CONTAINER is only for dedicated ai_worker containers", w.AssetID)
			}
		}
		if other, dup := r.byCID[w.ContainerID]; dup {
			return nil, fmt.Errorf("registry: container %s is enrolled twice (%s, %s)", w.ContainerID[:12], other, w.AssetID)
		}
		r.byCID[w.ContainerID] = w.AssetID
		r.workloads[w.AssetID] = w
	}
	return r, nil
}

func (r *Registry) Node() Node { return r.node }

// Workload looks up an enrolled asset.
func (r *Registry) Workload(assetID string) (Workload, bool) {
	w, ok := r.workloads[assetID]
	return w, ok
}

// ByContainer resolves a full container id to its enrolled asset.
func (r *Registry) ByContainer(cid string) (Workload, bool) {
	a, ok := r.byCID[cid]
	if !ok {
		return Workload{}, false
	}
	return r.workloads[a], true
}

// Workloads returns a copy of every enrolled workload.
func (r *Registry) Workloads() []Workload {
	out := make([]Workload, 0, len(r.workloads))
	for _, w := range r.workloads {
		out = append(out, w)
	}
	return out
}

// Sensors returns a copy of every enrolled sensor (token hashes included; never log them).
func (r *Registry) Sensors() []Sensor {
	out := make([]Sensor, 0, len(r.sensors))
	for _, s := range r.sensors {
		out = append(out, s)
	}
	return out
}

// Changes is the difference between two snapshots, as the reload log line reports
// it: asset ids added, removed or changed in any field (profile, container,
// generation, permissions, team, active flag), and sensor names added or removed.
type Changes struct {
	Added, Removed, Changed      []string
	SensorsAdded, SensorsRemoved []string
}

// Compare diffs next against prev. Slices are empty, never nil, so the log line
// shows [] rather than null.
func Compare(prev, next *Registry) Changes {
	ch := Changes{Added: []string{}, Removed: []string{}, Changed: []string{}, SensorsAdded: []string{}, SensorsRemoved: []string{}}
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
			ch.Added = append(ch.Added, w.AssetID)
		case !reflect.DeepEqual(o, w):
			ch.Changed = append(ch.Changed, w.AssetID)
		}
		delete(old, w.AssetID)
	}
	for id := range old {
		ch.Removed = append(ch.Removed, id)
	}
	// Sensors are keyed by name: a rotated token under the same name is neither added
	// nor removed, the old token just stops authenticating.
	oldSensors := map[string]bool{}
	if prev != nil {
		for _, s := range prev.Sensors() {
			oldSensors[s.Name] = true
		}
	}
	for _, s := range next.Sensors() {
		if !oldSensors[s.Name] {
			ch.SensorsAdded = append(ch.SensorsAdded, s.Name)
		}
		delete(oldSensors, s.Name)
	}
	for n := range oldSensors {
		ch.SensorsRemoved = append(ch.SensorsRemoved, n)
	}
	for _, s := range []*[]string{&ch.Added, &ch.Removed, &ch.Changed, &ch.SensorsAdded, &ch.SensorsRemoved} {
		sort.Strings(*s)
	}
	return ch
}

// Empty reports whether nothing differs.
func (c Changes) Empty() bool {
	return len(c.Added)+len(c.Removed)+len(c.Changed)+len(c.SensorsAdded)+len(c.SensorsRemoved) == 0
}

// Authenticate resolves a bearer token to a sensor with a constant-time compare
// against every enrolled hash.
func (r *Registry) Authenticate(token string) (Sensor, bool) {
	if token == "" {
		return Sensor{}, false
	}
	sum := sha256.Sum256([]byte(token))
	h := hex.EncodeToString(sum[:])
	var found Sensor
	ok := false
	for known, s := range r.sensors {
		if subtle.ConstantTimeCompare([]byte(h), []byte(known)) == 1 {
			found, ok = s, true
		}
	}
	return found, ok
}

// Identity builds the trusted identity for an enrolled workload.
func (r *Registry) Identity(w Workload) policy.Identity {
	return policy.Identity{TenantID: r.node.TenantID, AssetID: w.AssetID, HostID: r.node.HostID,
		Generation: w.Generation, ContainerID: w.ContainerID, SessionID: w.SessionID}
}

// Holder lets the controller swap registry snapshots atomically.
type Holder struct {
	mu sync.RWMutex
	r  *Registry
}

func NewHolder(r *Registry) *Holder { return &Holder{r: r} }

func (h *Holder) Get() *Registry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.r
}

func (h *Holder) Set(r *Registry) {
	h.mu.Lock()
	h.r = r
	h.mu.Unlock()
}
