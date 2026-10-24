package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func falcoWatch() *Watchlist {
	w := newWatchlist()
	w.replace(nil, map[string]WorkloadRef{cidA: {ID: "worker-01", Name: "W", Profile: "diagnostic-worker", Kind: "ai_worker", Enrolled: true, ContainerID: cidA}})
	return w
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const falcoOpen = `{"hostname":"vm","output":"river3 open ...","priority":"Debug","rule":"river3_open","source":"syscall","time":"2026-10-19T04:00:00.123456789Z","output_fields":{"container.id":"aaaaaaaaaaaa","container.full_id":"` + cidA + `","evt.arg.flags":"O_RDONLY|O_CLOEXEC","evt.arg.name":"settings","evt.rawres":7,"evt.rawtime":1792382400123456789,"evt.res":"SUCCESS","evt.type":"openat","fd.name":"/opt/config/.db_recovery_creds","proc.name":"python3","proc.pid":4242,"proc.ppid":1,"user.uid":1000}}`

const falcoExec = `{"rule":"river3_exec","source":"syscall","time":"2026-10-19T04:00:01Z","output_fields":{"container.id":"aaaaaaaaaaaa","evt.arg.filename":"/usr/bin/curl","evt.rawres":0,"evt.rawtime":1792382401000000000,"evt.res":"SUCCESS","evt.type":"execve","proc.cmdline":"curl -s http://203.0.113.9/x","proc.exepath":"/usr/bin/curl","proc.name":"curl","proc.pid":4243,"proc.ppid":4242,"user.uid":1000}}`

const falcoConnect = `{"rule":"river3_connect","source":"syscall","time":"2026-10-19T04:00:02Z","output_fields":{"container.full_id":"` + cidA + `","evt.rawres":-115,"evt.rawtime":1792382402000000000,"evt.res":"EINPROGRESS","evt.type":"connect","fd.l4proto":"tcp","fd.rip":"203.0.113.9","fd.rport":80,"fd.sip":"10.88.0.2","proc.name":"curl","proc.pid":4243,"proc.ppid":4242,"user.uid":1000}}`

func TestFalcoMapsOpenExecConnect(t *testing.T) {
	fa := &FalcoAdapter{Sensor: "falco", Watch: falcoWatch()}
	a, _ := parseFalco([]byte(falcoOpen))
	ev, ok := fa.Map(a)
	if !ok {
		t.Fatal("open not mapped")
	}
	f := ev.Facts
	if f.Kind != KindFileOpen || f.Outcome != OutcomeSuccess || f.Target.Path != "/opt/config/.db_recovery_creds" || !f.Target.PathResolved || f.Target.Access != "read" {
		t.Fatalf("%+v", f)
	}
	if f.Workload.ID != "worker-01" || f.Workload.ContainerID != cidA || f.Received != 1792382400123456789 || f.Process.PID != 4242 {
		t.Fatalf("%+v", f)
	}

	a, _ = parseFalco([]byte(falcoExec))
	ev, ok = fa.Map(a) // short container id resolves by prefix
	if !ok || ev.Facts.Kind != KindProcessExec || ev.Facts.Target.Exe != "/usr/bin/curl" || ev.Facts.Target.BinaryClass != "NET_CLIENT" {
		t.Fatalf("%v %+v", ok, ev.Facts)
	}
	if len(ev.Payload.Argv) != 3 || ev.Payload.Argv[0] != "curl" {
		t.Fatal(ev.Payload)
	}

	a, _ = parseFalco([]byte(falcoConnect))
	ev, ok = fa.Map(a)
	if !ok || ev.Facts.Kind != KindNetConnect || ev.Facts.Outcome != OutcomePending || ev.Facts.Errno != 115 || ev.Facts.Target.IP != "203.0.113.9" || ev.Facts.Target.Port != 80 {
		t.Fatalf("%v %+v", ok, ev.Facts)
	}
	if fa.Mapped != 3 {
		t.Fatal(fa.Mapped)
	}
}

func TestFalcoDropsUnenrolledHostAndOtherRules(t *testing.T) {
	fa := &FalcoAdapter{Sensor: "falco", Watch: falcoWatch()}
	cases := []string{
		strings.Replace(falcoOpen, cidA, strings.Repeat("b", 64), 1),                            // other container
		strings.Replace(strings.Replace(falcoOpen, cidA, "", 1), `"aaaaaaaaaaaa"`, `"host"`, 1), // host process
		`{"rule":"Terminal shell in container","output_fields":{"container.id":"aaaaaaaaaaaa","evt.type":"execve"}}`,
	}
	for i, c := range cases {
		a, err := parseFalco([]byte(c))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := fa.Map(a); ok {
			t.Fatalf("case %d mapped", i)
		}
	}
	// host process and a foreign rule are ignored; the other container is unenrolled.
	if fa.Unenrolled != 1 || fa.Ignored != 2 {
		t.Fatalf("unenrolled=%d ignored=%d", fa.Unenrolled, fa.Ignored)
	}
}

func TestFalcoFailedOpenUsesRawName(t *testing.T) {
	fa := &FalcoAdapter{Sensor: "falco", Watch: falcoWatch()}
	line := strings.Replace(falcoOpen, `"evt.rawres":7`, `"evt.rawres":-2`, 1)
	line = strings.Replace(line, `"fd.name":"/opt/config/.db_recovery_creds"`, `"fd.name":""`, 1)
	a, _ := parseFalco([]byte(line))
	ev, _ := fa.Map(a)
	if ev.Facts.Outcome != OutcomeFailed || ev.Facts.Errno != 2 || ev.Facts.Target.Path != "settings" || ev.Facts.Target.PathResolved {
		t.Fatalf("%+v", ev.Facts)
	}
}

func TestFalcoStreamAndHTTP(t *testing.T) {
	fa := &FalcoAdapter{Sensor: "falco", Watch: falcoWatch()}
	var got []Event
	emit := func(e Event) { got = append(got, e) }
	in := falcoOpen + "\n\nnot json\n" + falcoExec + "\n"
	if err := fa.ReadStream(context.Background(), strings.NewReader(in), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || fa.Ignored != 1 {
		t.Fatalf("got %d ignored %d", len(got), fa.Ignored)
	}
	srv := httptest.NewServer(fa.Handler(emit))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/falco", "application/json", strings.NewReader(falcoConnect))
	if err != nil || resp.StatusCode != 202 || len(got) != 3 {
		t.Fatalf("%v %d %d", err, resp.StatusCode, len(got))
	}
}

func TestFalcoEventIsStrictlyDecodableByTheController(t *testing.T) {
	// Same contract pin as the eBPF path: only known keys.
	fa := &FalcoAdapter{Sensor: "falco", Watch: falcoWatch()}
	a, _ := parseFalco([]byte(falcoExec))
	ev, _ := fa.Map(a)
	js := mustJSON(t, ev)
	for _, w := range []string{`"facts":{"id":"ev-`, `"kind":"process_exec"`, `"exe":"/usr/bin/curl"`, `"path_resolved":true`, `"payload":{"argv":[`} {
		if !strings.Contains(js, w) {
			t.Fatalf("missing %s in %s", w, js)
		}
	}
	if strings.Contains(js, "output_fields") || strings.Contains(js, "rule") {
		t.Fatal("falco-specific keys leaked into the event")
	}
}
