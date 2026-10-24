package main

// Falco adapter: the sensor for the Mac, where the eBPF program cannot run on the
// host and Falco runs inside the podman machine VM instead.
//
// Falco is configured with falco/river3_rules.yaml and json_output=true. Each
// alert is one JSON line; this adapter maps the fields those rules emit onto the
// same Event shape the eBPF path produces, so everything downstream (controller,
// API, console) is identical. Input is a stream of JSON lines (stdin, a file, or
// Falco's http_output pointed at -falco-listen).
//
// Trust notes: Falco already resolved fd.name / proc.exepath to absolute paths
// inside the container, so PathResolved is true for those; the raw filename of a
// failed open is not resolved. The container id is matched against enrollment, so
// an alert for an unenrolled container is dropped exactly like an unwatched mntns.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type falcoAlert struct {
	Rule         string         `json:"rule"`
	Time         string         `json:"time"`
	Source       string         `json:"source"`
	OutputFields map[string]any `json:"output_fields"`
}

type FalcoAdapter struct {
	Sensor string
	Watch  *Watchlist
	Now    func() time.Time
	// Hosts names connect destinations from the sensor's resolver (-resolve-hosts); may be nil.
	Hosts hostLookup
	// counters
	Mapped, Unenrolled, Ignored uint64
}

func (f *FalcoAdapter) str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case json.Number:
		return v.String()
	}
	return ""
}

func (f *FalcoAdapter) i64(m map[string]any, k string) (int64, bool) {
	switch v := m[k].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// Map converts one alert. ok is false when the alert is not one of ours or the
// container is not enrolled.
func (f *FalcoAdapter) Map(a falcoAlert) (Event, bool) {
	m := a.OutputFields
	if m == nil || !strings.HasPrefix(a.Rule, "river3_") {
		f.Ignored++ // other rule sets do not carry the fields we need
		return Event{}, false
	}
	cid := f.str(m, "container.full_id")
	if cid == "" {
		cid = f.str(m, "container.id")
	}
	if cid == "" || cid == "host" {
		f.Ignored++
		return Event{}, false
	}
	ref, ok := f.Watch.LookupContainer(cid)
	if !ok {
		f.Unenrolled++
		return Event{}, false
	}

	var kind Kind
	switch f.str(m, "evt.type") {
	case "open", "openat", "openat2":
		kind = KindFileOpen
	case "execve", "execveat":
		kind = KindProcessExec
	case "connect":
		kind = KindNetConnect
	default:
		f.Ignored++
		return Event{}, false
	}

	rawres, hasRes := f.i64(m, "evt.rawres")
	outcome, errno := OutcomeSuccess, int64(0)
	switch {
	case !hasRes:
		outcome = Outcome("unknown")
	case rawres < 0 && kind == KindNetConnect && f.str(m, "evt.res") == "EINPROGRESS":
		outcome, errno = OutcomePending, -rawres
	case rawres < 0:
		outcome, errno = OutcomeFailed, -rawres
	}

	ts, _ := f.i64(m, "evt.rawtime")
	if ts == 0 {
		if t, err := time.Parse(time.RFC3339Nano, a.Time); err == nil {
			ts = t.UnixNano()
		} else if f.Now != nil {
			ts = f.Now().UnixNano()
		} else {
			ts = time.Now().UnixNano()
		}
	}
	pid, _ := f.i64(m, "proc.pid")
	ppid, _ := f.i64(m, "proc.ppid")
	uid, _ := f.i64(m, "user.uid")

	sum := sha256.Sum256([]byte(fmt.Sprintf("falco|%s|%s|%d|%d|%s", f.Sensor, cid, pid, ts, kind)))
	facts := Facts{
		ID: "ev-" + hex.EncodeToString(sum[:12]), Sensor: f.Sensor, Kind: kind, Outcome: outcome, Errno: errno,
		Workload:   ref,
		Process:    ProcessRef{PID: uint32(pid), TGID: uint32(pid), PPID: uint32(ppid), UID: uint32(uid), Comm: f.str(m, "proc.name")},
		KernelExit: uint64(ts), Received: uint64(ts),
	}
	ev := Event{Facts: facts}
	switch kind {
	case KindFileOpen:
		name := f.str(m, "fd.name")
		resolved := strings.HasPrefix(name, "/")
		if name == "" {
			name = f.str(m, "evt.arg.name")
			if name == "" {
				name = f.str(m, "evt.arg.filename")
			}
			resolved = false
		}
		facts.Target.Path, facts.Target.PathResolved = name, resolved
		facts.Target.Access = falcoAccess(f.str(m, "evt.arg.flags"))
	case KindProcessExec:
		exe := f.str(m, "proc.exepath")
		resolved := strings.HasPrefix(exe, "/")
		if exe == "" {
			exe = f.str(m, "evt.arg.filename")
			resolved = false
		}
		facts.Target.Exe, facts.Target.PathResolved = exe, resolved
		facts.Target.BinaryClass, facts.Target.BinaryDetail = classifyBinary(exe)
		if cmd := f.str(m, "proc.cmdline"); cmd != "" {
			ev.Payload.Argv = strings.Fields(cmd) // lossy on quoted args; Channel B only
		}
	case KindNetConnect:
		facts.Target.IP = f.str(m, "fd.rip")
		if facts.Target.IP == "" {
			facts.Target.IP = f.str(m, "fd.sip")
		}
		if p, ok := f.i64(m, "fd.rport"); ok && p > 0 && p < 65536 {
			facts.Target.Port = uint16(p)
		}
		if f.Hosts != nil && facts.Target.IP != "" {
			facts.Target.Host, _ = f.Hosts.Lookup(facts.Target.IP)
		}
	}
	ev.Facts = facts
	f.Mapped++
	return ev, true
}

// falcoAccess maps an open(2) flags string such as "O_RDWR|O_CREAT|O_CLOEXEC".
func falcoAccess(flags string) string {
	switch {
	case strings.Contains(flags, "O_RDWR"):
		return "rw"
	case strings.Contains(flags, "O_WRONLY"):
		return "write"
	case flags == "":
		return ""
	}
	return "read"
}

// parseFalco decodes one alert keeping integers exact (evt.rawtime is nanoseconds
// since the epoch and would lose precision as a float64).
func parseFalco(line []byte) (falcoAlert, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var a falcoAlert
	err := dec.Decode(&a)
	return a, err
}

// ReadStream consumes JSON lines until EOF or ctx ends.
func (f *FalcoAdapter) ReadStream(ctx context.Context, r io.Reader, emit func(Event)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		a, err := parseFalco(line)
		if err != nil {
			f.Ignored++
			continue
		}
		if ev, ok := f.Map(a); ok {
			emit(ev)
		}
	}
	return sc.Err()
}

// Handler accepts Falco's http_output (one JSON alert per POST, or JSON lines).
func (f *FalcoAdapter) Handler(emit func(Event)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := http.MaxBytesReader(w, r.Body, 1<<20)
		if err := f.ReadStream(r.Context(), body, emit); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
