package journal

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T, path string) *Journal {
	t.Helper()
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func TestReserveIsDurableAndExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j")
	j := open(t, p)
	if _, err := j.Reserve("k1", "PAUSE_CONTAINER", "cid", "asset", "ev"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Reserve("k1", "PAUSE_CONTAINER", "cid", "asset", "ev"); !errors.Is(err, ErrDuplicate) {
		t.Fatal(err)
	}
	j.Close()
	j2 := open(t, p)
	if _, err := j2.Reserve("k1", "PAUSE_CONTAINER", "cid", "asset", "ev"); !errors.Is(err, ErrDuplicate) {
		t.Fatal("reservation lost across reopen")
	}
	inflight := j2.InFlight()
	if len(inflight) != 1 || inflight[0].State != Reserved {
		t.Fatalf("%+v", inflight)
	}
}

func TestTerminalStatesAreFinal(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "j"))
	_, _ = j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "ev")
	if err := j.Transition("k", Executing, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := j.Transition("k", Verified, map[string]any{"ok": true}, 12.5); err != nil {
		t.Fatal(err)
	}
	if err := j.Transition("k", Failed, nil, 0); err == nil {
		t.Fatal("terminal state changed")
	}
	a, _ := j.Action("k")
	if a.State != Verified || a.Latency != 12.5 || a.Detail["ok"] != true {
		t.Fatalf("%+v", a)
	}
	ev, _ := j.Event("ev")
	if !ev.HasResponse || ev.ActionKey != "k" {
		t.Fatalf("%+v", ev)
	}
}

func TestDecisionDuplicate(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "j"))
	fresh, _ := j.RecordDecision("e", map[string]any{"x": 1}, true)
	again, _ := j.RecordDecision("e", map[string]any{"x": 2}, true)
	if !fresh || again {
		t.Fatal(fresh, again)
	}
}

func TestPendingAndReportSteps(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "j"))
	_, _ = j.RecordDecision("e", map[string]any{}, true)
	if p := j.Pending(); len(p) != 1 {
		t.Fatalf("%+v", p)
	}
	_ = j.MarkIncidentCreated("e", "inc_1")
	if p := j.Pending(); len(p) != 0 {
		t.Fatalf("incident created but still pending: %+v", p)
	}
	_, _ = j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e")
	_ = j.Transition("k", Executing, nil, 0)
	_ = j.Transition("k", Failed, nil, 0)
	if p := j.Pending(); len(p) != 1 {
		t.Fatal("terminal action must make the event pending until reported")
	}
	_ = j.MarkResponseReported("e")
	if p := j.Pending(); len(p) != 0 {
		t.Fatal(p)
	}
	_, _ = j.RecordDecision("o", map[string]any{}, true)
	_ = j.MarkOrphaned("o", "409")
	if p := j.Pending(); len(p) != 0 {
		t.Fatal("orphaned event must not be retried")
	}
	if s := j.Stats(); s.Orphaned != 1 || s.Failed != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestOperatorRecords(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "j"))
	ok, _ := j.ClaimOperator("a1", map[string]any{"action": "resume"})
	dup, _ := j.ClaimOperator("a1", nil)
	if !ok || dup {
		t.Fatal(ok, dup)
	}
	if h := j.HandlingOperators(); len(h) != 1 || h[0].Detail["action"] != "resume" {
		t.Fatalf("claim not visible as in flight: %+v", h)
	}
	_ = j.FinishOperator("a1", "completed", map[string]any{"workload_state": "running"})
	if h := j.HandlingOperators(); len(h) != 0 {
		t.Fatalf("finished claim still in flight: %+v", h)
	}
	if u := j.UnreportedOperators(); len(u) != 1 || u[0].Result != "completed" {
		t.Fatalf("%+v", u)
	}
	_ = j.MarkOperatorReported("a1")
	if u := j.UnreportedOperators(); len(u) != 0 {
		t.Fatal(u)
	}
}

func TestInScopeDecisionsOweNothing(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "j"))
	_, _ = j.RecordDecision("quiet", map[string]any{}, false)
	if len(j.Pending()) != 0 || j.Stats().PendingReports != 0 {
		t.Fatal("unreported decision counted as pending")
	}
}

func TestTornTailIsToleratedCorruptionIsNot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j")
	j := open(t, p)
	_, _ = j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e")
	j.Close()

	// crash mid-write: a partial last line
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":2,"kind":"action","key":"k","sta`)
	f.Close()
	j2, err := Open(p)
	if err != nil {
		t.Fatalf("torn tail rejected: %v", err)
	}
	if a, _ := j2.Action("k"); a.State != Reserved {
		t.Fatal(a)
	}
	j2.Close()

	// garbage in the middle is corruption
	_ = os.WriteFile(p, []byte("{\"seq\":1,\"kind\":\"action\",\"key\":\"k\",\"state\":\"RESERVED\"}\nnot json\n{\"seq\":2,\"kind\":\"action\",\"key\":\"k\",\"state\":\"EXECUTING\"}\n"), 0o600)
	if _, err := Open(p); err == nil {
		t.Fatal("corrupt journal accepted")
	}
}

// everyLineParses reads the raw file and fails if any line is not one JSON record:
// the invariant the torn-tail repair exists to protect.
func everyLineParses(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		n++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("line %d is not one record: %q", n, sc.Text())
		}
	}
	data, _ := os.ReadFile(path)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		t.Fatal("file does not end in a newline")
	}
	return n
}

func TestTornTailIsTruncatedSoTheNextAppendOwnsItsLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j")
	j := open(t, p)
	_, _ = j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e")
	j.Close()

	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":2,"kind":"action","key":"k","sta`)
	f.Close()

	// Open repairs the tail; the next append must not share the torn line.
	j2 := open(t, p)
	if err := j2.Transition("k", Executing, nil, 0); err != nil {
		t.Fatal(err)
	}
	j2.Close()
	if n := everyLineParses(t, p); n != 2 {
		t.Fatalf("expected 2 clean records, got %d", n)
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), `"sta{`) {
		t.Fatalf("fragment shared a line with the next record:\n%s", data)
	}

	// The fsync'd record written after the repair survives a further reopen.
	j3 := open(t, p)
	if a, _ := j3.Action("k"); a.State != Executing {
		t.Fatalf("record lost after reopen: %+v", a)
	}
	if _, err := j3.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e"); !errors.Is(err, ErrDuplicate) {
		t.Fatal("reservation lost")
	}
}

func TestUnterminatedCompleteRecordIsKeptAndTerminated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j")
	j := open(t, p)
	_, _ = j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e")
	j.Close()

	// The bytes of the record landed, the trailing newline did not.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":2,"kind":"action","key":"k","state":"EXECUTING"}`)
	f.Close()

	j2 := open(t, p)
	if a, _ := j2.Action("k"); a.State != Executing {
		t.Fatalf("complete unterminated record dropped: %+v", a)
	}
	if err := j2.Transition("k", Verified, nil, 0); err != nil {
		t.Fatal(err)
	}
	j2.Close()
	if n := everyLineParses(t, p); n != 3 {
		t.Fatalf("expected 3 clean records, got %d", n)
	}
	j3 := open(t, p)
	if a, _ := j3.Action("k"); a.State != Verified {
		t.Fatalf("%+v", a)
	}
}

func TestEmptyJournalAndNewlineOnlyTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j")
	_ = os.WriteFile(p, []byte("\n"), 0o600)
	j := open(t, p)
	if _, err := j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e"); err != nil {
		t.Fatal(err)
	}
	j.Close()
	everyLineParses(t, p)
}

// TestTwoRecordsPlusTornFragmentThenAppendReopensWithThree is the review's exact
// scenario: two complete records, a torn fragment, Open, one append, Close, Open.
// Before the repair the append landed on the fragment's line and the second Open
// refused the journal as corrupt.
func TestTwoRecordsPlusTornFragmentThenAppendReopensWithThree(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j")
	j := open(t, p)
	if _, err := j.Reserve("k", "PAUSE_CONTAINER", "cid", "a", "e"); err != nil {
		t.Fatal(err)
	}
	if err := j.Transition("k", Executing, nil, 0); err != nil {
		t.Fatal(err)
	}
	j.Close()
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":3,"kind":"action","key":"k","state":"VERI`)
	f.Close()

	j2, err := Open(p)
	if err != nil {
		t.Fatalf("torn tail refused: %v", err)
	}
	if err := j2.Transition("k", Verified, map[string]any{"after": "repair"}, 1); err != nil {
		t.Fatal(err)
	}
	j2.Close()

	j3, err := Open(p)
	if err != nil {
		t.Fatalf("journal corrupt after an append onto a repaired tail: %v", err)
	}
	defer j3.Close()
	if n := everyLineParses(t, p); n != 3 {
		t.Fatalf("expected 3 records, got %d", n)
	}
	if a, _ := j3.Action("k"); a.State != Verified || a.Detail["after"] != "repair" {
		t.Fatalf("%+v", a)
	}
}
