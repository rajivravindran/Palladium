package normalize

import (
	"path"
	"regexp"
	"strings"
)

// The executable classification table lives in the controller, not the sensor,
// so a compromised or outdated sensor cannot choose its own class. It mirrors
// river3d/event.go; river3d's event_test keeps both within the engine's vocabulary.
//
// Limit: this classifies by the basename of the executable path the kernel
// reported, so on its own a renamed or copied binary classifies as OTHER. The
// river3d sensor closes that gap by hashing the running file and reporting the
// class of its content (exe_sha256, renamed, foreign_binary); normalize.go trusts
// that class from a path-resolving sensor and keeps this table for the name side
// of the comparison and for sensors without the capability.

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

var detailToClass = map[string]string{
	"NET_CLIENT": "NET_CLIENT", "SHELL": "INTERPRETER", "INTERPRETER": "INTERPRETER",
	"PRIV_ESC": "PRIVILEGED_TOOL", "RECON": "PRIVILEGED_TOOL", "FILE_UTIL": "DIAGNOSTIC",
	"ENCODER": "DIAGNOSTIC", "PKG": "NET_CLIENT", "OTHER": "OTHER",
}

var classOverride = map[string]string{
	"openssl": "NET_CLIENT", "nmap": "NET_CLIENT",
	"ip": "DIAGNOSTIC", "ifconfig": "DIAGNOSTIC", "netstat": "DIAGNOSTIC", "ss": "DIAGNOSTIC",
}

// Classify returns (engine class, sensor-style detail) for an executable path.
func Classify(exe string) (string, string) {
	base := path.Base(exe)
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

// engineClasses is the vocabulary a sensor-supplied class must belong to; it is
// derived from this table so the two cannot drift apart.
var engineClasses = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range detailToClass {
		m[c] = true
	}
	for _, c := range classOverride {
		m[c] = true
	}
	return m
}()

var (
	sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A detail is a label (NET_CLIENT, UNKNOWN_BINARY), optionally qualified by a
	// basename (RENAMED:curl) or an evidence marker (:NAME_ONLY). Anything else is
	// not written into an incident.
	detailRe = regexp.MustCompile(`^[A-Z_]{1,32}(:[A-Za-z0-9._+-]{1,64})?$`)
)

func isSHA256Hex(s string) bool { return sha256HexRe.MatchString(s) }

func validDetail(s string) bool { return detailRe.MatchString(s) }
