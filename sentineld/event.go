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
)

type WorkloadRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Profile  string `json:"profile"`
	Kind     string `json:"kind"`
	Enrolled bool   `json:"enrolled"`
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
	BinaryClass  string `json:"binary_class,omitempty"`
	IP           string `json:"ip,omitempty"`
	Port         uint16 `json:"port,omitempty"`
}

// Facts is Channel A: typed, structural, no free text from the workload
// except identifiers (paths / exe names) that are matched, never interpreted.
type Facts struct {
	ID          string      `json:"id"`
	Sensor      string      `json:"sensor"`
	Kind        Kind        `json:"kind"`
	Outcome     Outcome     `json:"outcome"`
	Errno       int64       `json:"errno,omitempty"`
	Workload    WorkloadRef `json:"workload"`
	Process     ProcessRef  `json:"process"`
	Target      Target      `json:"target"`
	KernelEnter uint64      `json:"t_kernel_enter_ns"`
	KernelExit  uint64      `json:"t_kernel_exit_ns"`
	Received    uint64      `json:"t_received_ns"`
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
// ---------------------------------------------------------------------------

var binaryClasses = map[string]string{
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

func classifyBinary(exe string) string {
	base := filepath.Base(exe)
	if c, ok := binaryClasses[base]; ok {
		return c
	}
	if strings.HasPrefix(base, "python") {
		return "INTERPRETER"
	}
	return "OTHER"
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
