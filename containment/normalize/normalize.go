// Package normalize is the trusted normalizer and context provider.
//
// It turns an authenticated river3d sensor event into a policy.Event and builds
// the policy.Context exclusively from controller-owned state: the enrollment
// registry, the authenticated sensor's declared capabilities and a live runtime
// inspection. Nothing in the event can set a trust flag. Anything that cannot
// be resolved is left unverified (the engine then blocks it) and the reason is
// recorded in Result.Notes so the incident says why.
package normalize

import (
	"context"
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// Raw mirrors river3d's Facts (Channel A). Payload (Channel B) is kept apart and
// never reaches the engine. Unknown fields are rejected by the strict decoder.
type Raw struct {
	Facts   RawFacts       `json:"facts"`
	Payload map[string]any `json:"payload"`
}

type RawFacts struct {
	ID       string      `json:"id"`
	Sensor   string      `json:"sensor"`
	Kind     string      `json:"kind"`
	Outcome  string      `json:"outcome"`
	Errno    int64       `json:"errno,omitempty"`
	Workload RawWorkload `json:"workload"`
	Process  RawProcess  `json:"process"`
	Target   RawTarget   `json:"target"`
	// Inline is set by river3d for events its BPF-LSM source observed (CONTRACTS.md
	// §8): the hook ran before the operation, whether or not it refused it. It is a
	// provenance note for the incident, never a trust flag.
	Inline      bool   `json:"inline,omitempty"`
	KernelEnter uint64 `json:"t_kernel_enter_ns,omitempty"`
	KernelExit  uint64 `json:"t_kernel_exit_ns,omitempty"`
	Received    uint64 `json:"t_received_ns,omitempty"`
}

type RawWorkload struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Profile     string `json:"profile,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Enrolled    bool   `json:"enrolled,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	// Team is the sensor's copy of the river3.team label (CONTRACTS.md §4.3, §6).
	// It only ever fills an empty team on the API's workload record; the registry's
	// own team (file or discovered label) wins when it has one.
	Team string `json:"team,omitempty"`
}

// MaxTeam bounds workload.team (CONTRACTS.md §6: string ≤64).
const MaxTeam = 64

// InlineNote is appended to the incident reason for an event the sensor saw inline.
const InlineNote = "observed inline by the sensor (LSM)"

type RawProcess struct {
	PID  uint32 `json:"pid,omitempty"`
	TGID uint32 `json:"tgid,omitempty"`
	PPID uint32 `json:"ppid,omitempty"`
	UID  uint32 `json:"uid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

type RawTarget struct {
	Path         string `json:"path,omitempty"`
	PathResolved bool   `json:"path_resolved,omitempty"`
	Access       string `json:"access,omitempty"`
	Exe          string `json:"exe,omitempty"`
	BinaryClass  string `json:"binary_class,omitempty"`
	BinaryDetail string `json:"binary_detail,omitempty"`
	IP           string `json:"ip,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	// Binary identity from a sensor that hashes /proc/<pid>/exe (river3d binident.go).
	ExeSHA256     string `json:"exe_sha256,omitempty"`
	ExeDev        uint64 `json:"exe_dev,omitempty"`
	ExeIno        uint64 `json:"exe_ino,omitempty"`
	ExeSize       uint64 `json:"exe_size,omitempty"`
	Renamed       bool   `json:"renamed,omitempty"`
	ForeignBinary bool   `json:"foreign_binary,omitempty"`
}

// Envelope is what the controller hands the normalizer: the raw event plus the
// facts the controller itself established about how the event arrived.
type Envelope struct {
	Raw        Raw
	Sensor     registry.Sensor // zero value when the transport was not authenticated
	Authentic  bool            // bearer token matched an enrolled sensor
	ReceivedAt time.Time       // controller clock at receipt
	Provenance policy.Provenance
}

// Result is everything the controller needs for Evaluate plus the display facts
// (Channel A only) it will attach to the incident.
type Result struct {
	Event    policy.Event
	Context  policy.Context
	Workload registry.Workload
	Enrolled bool
	Notes    []string // why a trust flag is false; fed into the incident reason
	Facts    map[string]any
	Payload  map[string]any
	// Team is what the API's workload record should carry: the registry's team when
	// the enrolment names one, else the authenticated sensor's label copy (≤64).
	Team string
}

// Normalizer holds the trusted inputs. Runtime inspection is optional for pure
// mapping tests; without it identity is never verified.
type Normalizer struct {
	Registry *registry.Holder
	Adapter  adapter.Adapter
	// Sessions is the session adapter (CONTRACTS.md §2.1), if one is configured. Its
	// Actions() are added to Context.AdapterActions so REVOKE_SESSION is not blocked
	// with ADAPTER_UNAVAILABLE when there is something to carry it out.
	Sessions adapter.SessionAdapter
	// HeartbeatWithin bounds how old the sensor's last message may be for the
	// workload to count as healthy. Zero disables the check.
	HeartbeatWithin time.Duration
	heartbeat       func(sensor string) time.Time
	session         func(assetID string) string
}

// SetHeartbeat wires a sensor liveness source (last message time per sensor).
func (n *Normalizer) SetHeartbeat(f func(sensor string) time.Time) { n.heartbeat = f }

// SetSession wires the controller's workload → active session map (CONTRACTS.md
// §1.4, filled from GET /api/v1/sessions?state=active). The function returns "" when
// the API knows no active session for the asset; the identity then keeps whatever
// the enrolment itself said (usually nothing) and the engine blocks REVOKE_SESSION
// with NO_BOUND_SESSION, exactly as before sessions existed. The event itself can
// never name a session: river3d does not send one and the strict decoder would
// reject it if it did.
func (n *Normalizer) SetSession(f func(assetID string) string) { n.session = f }

// classifyOutcome maps the sensor vocabulary (CONTRACTS.md §9: success | failed |
// pending | blocked) onto the engine's. "blocked" is river3d's BPF-LSM hook
// returning -EPERM before the syscall did anything (`-block-decoys`): the operation
// did not happen, so for the engine it is a failed outcome and can never be a
// candidate for containment (OUTCOME_NOT_SUCCESSFUL). The fact that it was blocked
// inline, rather than failing on its own, is kept as a note for the incident.
func classifyOutcome(s string) policy.Outcome {
	switch s {
	case "success":
		return policy.Succeeded
	case "failed", "blocked":
		return policy.Failed
	case "pending":
		return policy.Attempted
	}
	return policy.UnknownOutcome
}

// BlockedNote is appended to the incident reason for a sensor outcome of "blocked".
const BlockedNote = "blocked inline by sensor"

func canonical(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || p != path.Clean(p) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	return !strings.HasSuffix(p, " (deleted)")
}

// Normalize never returns an engine-blocking error for untrusted input; it
// returns a Result whose Context leaves the relevant flags false. Errors are
// reserved for input that cannot be represented at all.
func (n *Normalizer) Normalize(ctx context.Context, env Envelope, now time.Time) (Result, error) {
	f := env.Raw.Facts
	res := Result{Notes: []string{}, Payload: env.Raw.Payload}
	if res.Payload == nil {
		res.Payload = map[string]any{}
	}
	if f.ID == "" {
		return res, fmt.Errorf("event has no id")
	}
	reg := n.Registry.Get()

	// --- identity: registry + runtime, never the event's own claims ---------
	w, enrolled := reg.Workload(f.Workload.ID)
	if !enrolled && f.Workload.ContainerID != "" {
		w, enrolled = reg.ByContainer(f.Workload.ContainerID)
	}
	res.Workload, res.Enrolled = w, enrolled
	identity := policy.Identity{TenantID: reg.Node().TenantID, HostID: reg.Node().HostID, AssetID: f.Workload.ID, Generation: "unenrolled"}
	if enrolled {
		identity = reg.Identity(w)
		// The session acting right now, as the API learned it from the gateway
		// (CONTRACTS.md §1.4). Any enrolled kind: a shared service's request session or
		// an AI worker's agent run. The map is controller state refreshed from the API,
		// never a field of the event.
		if n.session != nil {
			if sid := n.session(w.AssetID); sid != "" {
				identity.SessionID = sid
			}
		}
		res.Team = w.Team
	} else {
		res.Notes = append(res.Notes, "workload is not enrolled on this node")
		if identity.AssetID == "" {
			identity.AssetID = "unknown"
		}
	}
	pctx := policy.Context{ProfileName: w.Profile, ProfileVersion: 0, Identity: identity, Now: now}

	identityVerified := false
	healthy := false
	active := false
	if enrolled {
		// The sensor's container id (from the cgroup/mount namespace it observed)
		// must be the enrolled one, and the runtime must still show that exact
		// container in the enrolled generation. Both are checked here, and again
		// by Revalidate immediately before any action.
		if f.Workload.ContainerID != "" && f.Workload.ContainerID != w.ContainerID {
			res.Notes = append(res.Notes, "sensor container id differs from enrollment")
		} else if n.Adapter == nil {
			res.Notes = append(res.Notes, "no runtime adapter to confirm identity")
		} else {
			info, err := n.Adapter.Inspect(ctx, w.ContainerID)
			switch {
			case err != nil:
				res.Notes = append(res.Notes, "runtime inspection failed: "+err.Error())
			case info.Status == adapter.Missing:
				res.Notes = append(res.Notes, "enrolled container is missing from the runtime")
			case info.ContainerID != w.ContainerID:
				res.Notes = append(res.Notes, "runtime returned a different container id")
			case info.Generation != w.Generation:
				res.Notes = append(res.Notes, "runtime generation differs from enrollment (container restarted or replaced)")
			default:
				identityVerified = true
				healthy = true
				active = w.Active && info.Status == adapter.Running
				if !w.Active {
					res.Notes = append(res.Notes, "workload enrollment is inactive")
				} else if info.Status != adapter.Running {
					res.Notes = append(res.Notes, "container is "+string(info.Status)+", not running")
				}
			}
		}
		if healthy && n.HeartbeatWithin > 0 && n.heartbeat != nil && env.Authentic {
			last := n.heartbeat(env.Sensor.Name)
			if last.IsZero() || now.Sub(last) > n.HeartbeatWithin {
				healthy = false
				res.Notes = append(res.Notes, "sensor heartbeat is stale")
			}
		}
	}
	if !env.Authentic {
		res.Notes = append(res.Notes, "event did not arrive over an authenticated sensor channel")
	}
	pctx.IdentityVerified = identityVerified
	pctx.SensorAuthenticated = env.Authentic
	pctx.Healthy = healthy
	pctx.Active = active
	pctx.DedicatedContainer = w.Dedicated
	pctx.PermittedActions = append([]policy.Action(nil), w.PermittedActions...)
	if n.Adapter != nil {
		pctx.AdapterActions = append(pctx.AdapterActions, n.Adapter.Actions()...)
	}
	if n.Sessions != nil {
		pctx.AdapterActions = append(pctx.AdapterActions, n.Sessions.Actions()...)
	}
	// The sensor's team label is Channel A from an authenticated sensor, but it is
	// still a label, so it only ever fills a blank: the enrolment's team wins.
	if res.Team == "" && env.Authentic && f.Workload.Team != "" {
		if len(f.Workload.Team) <= MaxTeam {
			res.Team = f.Workload.Team
		} else {
			res.Notes = append(res.Notes, "sensor team label longer than 64 characters; ignored")
		}
	}

	// --- evidence ------------------------------------------------------------
	observed := env.ReceivedAt
	if f.Received > 0 {
		t := time.Unix(0, int64(f.Received)).UTC()
		// Only accept a sensor clock that is plausibly wall-clock and not ahead of us.
		if t.Year() >= 2020 && !t.After(now.Add(2*time.Second)) {
			observed = t
		} else {
			res.Notes = append(res.Notes, "sensor timestamp implausible; using receipt time")
		}
	}
	if observed.IsZero() {
		observed = now
	}
	ev := policy.Event{ID: f.ID, Identity: identity, ObservedAt: observed, Provenance: env.Provenance, Outcome: classifyOutcome(f.Outcome)}
	blocked := f.Outcome == "blocked"
	switch f.Outcome {
	case "success", "failed", "pending":
	case "blocked":
		res.Notes = append(res.Notes, BlockedNote)
	default:
		res.Notes = append(res.Notes, "sensor outcome unrecognised; treated as UNKNOWN")
	}
	target := map[string]any{}
	resourceVerified := false
	switch f.Kind {
	case "file_open":
		ev.Operation = policy.FileOpen
		ev.Path = f.Target.Path
		switch f.Target.Access {
		case "read":
			ev.OpenRead = true
		case "write":
			ev.OpenWrite = true
		case "rw":
			ev.OpenRead, ev.OpenWrite = true, true
		default:
			res.Notes = append(res.Notes, "open access mode missing")
		}
		target["path"] = f.Target.Path
		target["access"] = f.Target.Access
		if !canonical(f.Target.Path) {
			res.Notes = append(res.Notes, "path is not canonical")
		} else if !env.Authentic || !env.Sensor.ResolvesPaths {
			res.Notes = append(res.Notes, "sensor is not trusted to resolve paths")
		} else if !f.Target.PathResolved {
			res.Notes = append(res.Notes, "sensor did not resolve this path in the kernel")
		} else {
			resourceVerified = true
		}
	case "process_exec":
		ev.Operation = policy.ProcessExec
		// The name-based class is this controller's own table applied to the
		// executable path the kernel reported. A sensor that hashed the running file
		// and looked it up in the workload's image knows something this controller
		// never sees (the content), so its class is trusted when that evidence is
		// present and the sensor is one we trust to look at the filesystem; the
		// name-based class is kept alongside so a disagreement is on record.
		nameClass, nameDetail := Classify(f.Target.Exe)
		class, detail := nameClass, nameDetail
		target["exe"] = f.Target.Exe
		switch {
		case f.Target.ExeSHA256 == "":
			// Old sensor or Falco: the name is the only evidence, as before.
		case !isSHA256Hex(f.Target.ExeSHA256):
			res.Notes = append(res.Notes, "sensor exe_sha256 is malformed; ignored")
		case !env.Authentic || !env.Sensor.ResolvesPaths:
			res.Notes = append(res.Notes, "sensor is not trusted to identify binaries; class from name")
		case !engineClasses[f.Target.BinaryClass]:
			res.Notes = append(res.Notes, "sensor class "+f.Target.BinaryClass+" is not an engine class; class from name")
		default:
			class = f.Target.BinaryClass
			if validDetail(f.Target.BinaryDetail) {
				detail = f.Target.BinaryDetail
			}
			target["exe_sha256"] = f.Target.ExeSHA256
			if f.Target.ExeSize != 0 {
				target["exe_size"] = f.Target.ExeSize
			}
			if f.Target.Renamed {
				target["renamed"] = true
			}
			if f.Target.ForeignBinary {
				target["foreign_binary"] = true
			}
			if class != nameClass {
				res.Notes = append(res.Notes, "class from exe hash (sensor): "+class+"; name would be "+nameClass)
			}
		}
		if f.Target.BinaryClass != "" && f.Target.BinaryClass != class {
			res.Notes = append(res.Notes, "sensor class "+f.Target.BinaryClass+" overridden by controller table ("+class+")")
		}
		ev.BinaryClass = class
		target["binary_class"] = class
		target["binary_detail"] = detail
		if !canonical(f.Target.Exe) {
			res.Notes = append(res.Notes, "executable path is not canonical")
		} else if !env.Authentic || !env.Sensor.ResolvesPaths {
			res.Notes = append(res.Notes, "sensor is not trusted to resolve paths")
		} else {
			resourceVerified = true
		}
	case "net_connect":
		ev.Operation = policy.NetConnect
		ev.DestinationIP = f.Target.IP
		target["ip"] = f.Target.IP
		if f.Target.Port != 0 {
			target["port"] = f.Target.Port
		}
		if addr, err := netip.ParseAddr(f.Target.IP); err != nil || addr.Zone() != "" || addr.IsUnspecified() {
			res.Notes = append(res.Notes, "destination address unresolved")
		} else if env.Authentic {
			resourceVerified = true // the kernel saw this sockaddr; no DNS is involved
		}
	default:
		return res, fmt.Errorf("unsupported event kind %q", f.Kind)
	}
	pctx.ResourceVerified = resourceVerified
	if !resourceVerified && len(res.Notes) == 0 {
		res.Notes = append(res.Notes, "resource not verified")
	}
	if f.Inline {
		// Provenance, not a trust flag: the LSM hook saw the operation before it
		// happened (and, with outcome "blocked", refused it). Placed after the trust
		// notes so "resource not verified" is still written when it applies.
		res.Notes = append(res.Notes, InlineNote)
	}

	res.Event = ev
	res.Context = pctx
	res.Facts = map[string]any{
		"sensor":     f.Sensor,
		"operation":  string(ev.Operation),
		"outcome":    string(ev.Outcome),
		"provenance": string(env.Provenance),
		"identity":   identity,
		"process":    map[string]any{"pid": f.Process.PID, "ppid": f.Process.PPID, "uid": f.Process.UID, "comm": f.Process.Comm},
		"target":     target,
		"normalizer": map[string]any{"identity_verified": identityVerified, "resource_verified": resourceVerified,
			"sensor_authenticated": env.Authentic, "notes": res.Notes},
	}
	if f.Errno != 0 {
		res.Facts["errno"] = f.Errno
	}
	if f.Inline {
		res.Facts["inline"] = true
	}
	if res.Team != "" {
		res.Facts["workload"] = map[string]any{"team": res.Team}
	}
	if blocked {
		// The engine sees FAILED; the console should see that the sensor did it.
		res.Facts["sensor_outcome"] = "blocked"
		res.Facts["blocked_inline"] = true
	}
	return res, nil
}

// ProfileVersion must be filled by the controller from its loaded profile set;
// the registry binds a name, the engine snapshot owns the version.
func (r *Result) WithProfileVersion(v int) { r.Context.ProfileVersion = v }
