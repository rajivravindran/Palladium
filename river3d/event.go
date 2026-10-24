package main

import (
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Event = Channel A facts + Channel B payload, kept in SEPARATE structs.
//
// The policy engine's Evaluate() takes only Facts, so it is impossible (at
// compile time) for untrusted text such as command-line arguments to change a
// structural decision. Payload exists only for later Channel B analysis.
// ---------------------------------------------------------------------------

type Kind string

const (
	KindFileOpen    Kind = "file_open"
	KindProcessExec Kind = "process_exec"
	KindNetConnect  Kind = "net_connect"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailed  Outcome = "failed"
	OutcomePending Outcome = "pending" // e.g. non-blocking connect (EINPROGRESS)
	// OutcomeBlocked: the sensor itself denied the operation inline (BPF-LSM hook
	// returned -EPERM). Downstream treats it as a failed-class outcome (contract §9).
	OutcomeBlocked Outcome = "blocked"
)

type WorkloadRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Profile  string `json:"profile"`
	Kind     string `json:"kind"`
	Enrolled bool   `json:"enrolled"`
	// Full 64-hex container id from enrollment. The containment controller
	// binds identity on this, never on a label or a short id.
	ContainerID string `json:"container_id,omitempty"`
	// Team from the river3.team label (or the enrollment file); used by the API
	// for team scoping (contract §4.3, §6). Not an identity input.
	Team string `json:"team,omitempty"`
}

type ProcessRef struct {
	PID  uint32 `json:"pid"`
	TGID uint32 `json:"tgid"`
	PPID uint32 `json:"ppid"`
	UID  uint32 `json:"uid"`
	Comm string `json:"comm"`
}

type Target struct {
	Path         string `json:"path,omitempty"`
	PathResolved bool   `json:"path_resolved,omitempty"`
	Access       string `json:"access,omitempty"` // read | write | rw
	Exe          string `json:"exe,omitempty"`
	BinaryClass  string `json:"binary_class,omitempty"`  // policy-engine vocabulary (see EngineClasses)
	BinaryDetail string `json:"binary_detail,omitempty"` // finer sensor label, kept for context and tuning
	IP           string `json:"ip,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	// Host is the name the SENSOR resolved for IP (-resolve-hosts, hosts.go): one of
	// the profile's egress hostnames whose current addresses include IP. It is the
	// operator's name for the address, not what the workload asked DNS for. Absent
	// when the IP is not in the cache; the engine then matches CIDR rules only.
	Host string `json:"host,omitempty"`

	// Binary identity (binident.go): what the executed file IS, independent of its
	// name. Present only on successful execs from a sensor with the image index on.
	ExeSHA256     string `json:"exe_sha256,omitempty"` // "" when the file was too big or unreadable
	ExeDev        uint64 `json:"exe_dev,omitempty"`
	ExeIno        uint64 `json:"exe_ino,omitempty"`
	ExeSize       uint64 `json:"exe_size,omitempty"`
	Renamed       bool   `json:"renamed,omitempty"`        // image content executed under a name the image never gave it
	ForeignBinary bool   `json:"foreign_binary,omitempty"` // content not found in the workload's image at all
}

// Facts is Channel A: typed, structural, no free text from the workload
// except identifiers (paths / exe names) that are matched, never interpreted.
type Facts struct {
	ID       string      `json:"id"`
	Sensor   string      `json:"sensor"`
	Kind     Kind        `json:"kind"`
	Outcome  Outcome     `json:"outcome"`
	Errno    int64       `json:"errno,omitempty"`
	Workload WorkloadRef `json:"workload"`
	Process  ProcessRef  `json:"process"`
	Target   Target      `json:"target"`
	// Inline is true when the event came from a BPF-LSM hook, i.e. it was recorded
	// BEFORE the operation and the outcome is the sensor's decision (success =
	// allowed, blocked = denied), not the syscall's return value.
	Inline      bool   `json:"inline,omitempty"`
	KernelEnter uint64 `json:"t_kernel_enter_ns"`
	KernelExit  uint64 `json:"t_kernel_exit_ns"`
	Received    uint64 `json:"t_received_ns"`
}

// Payload is Channel B: untrusted material. Never passed to policy.Evaluate.
type Payload struct {
	Argv []string `json:"argv,omitempty"`
}

type Event struct {
	Facts   Facts   `json:"facts"`
	Payload Payload `json:"payload"`
	mntns   uint32
}

// ---------------------------------------------------------------------------
// Binary classes (Channel A summary of "what kind of tool is this")
//
// Two levels:
//   detail : the sensor's finer label (SHELL, FILE_UTIL, RECON, ...), kept for context
//   class  : the policy engine's vocabulary, the only value profiles match on
//
// The engine accepts exactly EngineClasses; anything else becomes UNKNOWN_EXEC_CLASS.
// event_test.go fails if this table ever emits a class outside that set.
// ---------------------------------------------------------------------------

// EngineClasses must stay in sync with `classes` in policy/profile.go.
var EngineClasses = []string{"DIAGNOSTIC", "INTERPRETER", "NET_CLIENT", "PRIVILEGED_TOOL", "OTHER"}

var binaryDetails = map[string]string{
	"curl": "NET_CLIENT", "wget": "NET_CLIENT", "nc": "NET_CLIENT", "ncat": "NET_CLIENT",
	"netcat": "NET_CLIENT", "socat": "NET_CLIENT", "ssh": "NET_CLIENT", "scp": "NET_CLIENT",
	"sftp": "NET_CLIENT", "ftp": "NET_CLIENT", "telnet": "NET_CLIENT", "rsync": "NET_CLIENT",
	"sh": "SHELL", "bash": "SHELL", "dash": "SHELL", "zsh": "SHELL", "ash": "SHELL",
	"python": "INTERPRETER", "python3": "INTERPRETER", "perl": "INTERPRETER", "ruby": "INTERPRETER",
	"node": "INTERPRETER", "php": "INTERPRETER", "lua": "INTERPRETER",
	"sudo": "PRIV_ESC", "su": "PRIV_ESC", "nsenter": "PRIV_ESC", "chroot": "PRIV_ESC",
	"mount": "PRIV_ESC", "umount": "PRIV_ESC", "unshare": "PRIV_ESC", "setcap": "PRIV_ESC",
	"insmod": "PRIV_ESC", "modprobe": "PRIV_ESC",
	"capsh": "RECON", "fdisk": "RECON", "lsblk": "RECON", "nmap": "RECON", "ip": "RECON",
	"ifconfig": "RECON", "netstat": "RECON", "ss": "RECON",
	"cat": "FILE_UTIL", "grep": "FILE_UTIL", "ls": "FILE_UTIL", "head": "FILE_UTIL",
	"tail": "FILE_UTIL", "wc": "FILE_UTIL", "cp": "FILE_UTIL", "mv": "FILE_UTIL",
	"rm": "FILE_UTIL", "mkdir": "FILE_UTIL", "find": "FILE_UTIL", "sed": "FILE_UTIL",
	"awk": "FILE_UTIL", "sort": "FILE_UTIL", "echo": "FILE_UTIL", "sleep": "FILE_UTIL",
	"env": "FILE_UTIL", "id": "FILE_UTIL", "whoami": "FILE_UTIL", "ps": "FILE_UTIL",
	"base64": "ENCODER", "xxd": "ENCODER", "openssl": "ENCODER", "gzip": "ENCODER", "tar": "ENCODER",
	"pip": "PKG", "pip3": "PKG", "npm": "PKG", "apt": "PKG", "apt-get": "PKG",
}

// detail -> engine class
var detailToClass = map[string]string{
	"NET_CLIENT":  "NET_CLIENT",
	"SHELL":       "INTERPRETER", // a shell runs arbitrary commands; profiles that allow `sh -c` must allow INTERPRETER
	"INTERPRETER": "INTERPRETER",
	"PRIV_ESC":    "PRIVILEGED_TOOL",
	"RECON":       "PRIVILEGED_TOOL",
	"FILE_UTIL":   "DIAGNOSTIC",
	"ENCODER":     "DIAGNOSTIC",
	"PKG":         "NET_CLIENT", // package managers fetch from the network
	"OTHER":       "OTHER",
}

// Per-binary exceptions where the detail group is too coarse.
var classOverride = map[string]string{
	"openssl":  "NET_CLIENT", // can open TLS connections (s_client)
	"nmap":     "NET_CLIENT",
	"ip":       "DIAGNOSTIC", // read-only network inspection in normal use
	"ifconfig": "DIAGNOSTIC",
	"netstat":  "DIAGNOSTIC",
	"ss":       "DIAGNOSTIC",
}

// classifyBinary returns (engine class, sensor detail) for an executable path.
func classifyBinary(exe string) (string, string) {
	base := filepath.Base(exe)
	detail, ok := binaryDetails[base]
	if !ok {
		detail = "OTHER"
		if strings.HasPrefix(base, "python") {
			detail = "INTERPRETER"
		}
	}
	if c, ok := classOverride[base]; ok {
		return c, detail
	}
	return detailToClass[detail], detail
}

// open(2) flags → access mode
func accessMode(flags uint32) string {
	switch flags & 3 {
	case 0:
		return "read"
	case 1:
		return "write"
	default:
		return "rw"
	}
}
