package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	policy "river3.local/policy"
	"strings"
	"testing"
)

func TestOfflineReplayNeverProducesCandidate(t *testing.T) {
	data, err := os.ReadFile("../../examples/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = run("../../examples/profiles", bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(out.String())
	}
	for i, line := range lines {
		var d policy.Decision
		if err = json.Unmarshal([]byte(line), &d); err != nil {
			t.Fatal(err)
		}
		if d.Candidate != nil || d.Action != policy.Alert || d.Mode != policy.Shadow {
			t.Fatal(d)
		}
		if i == 1 && (d.Status != policy.Violation || d.RecommendedAction != policy.Pause) {
			t.Fatal(d)
		}
	}
}
func TestCLIRejectsForgedContext(t *testing.T) {
	var out bytes.Buffer
	err := run("../../examples/profiles", strings.NewReader(`{"profile":"diagnostic-worker","context":{"IdentityVerified":true},"event":{}}`), &out)
	if err == nil {
		t.Fatal("accepted external context")
	}
}
func TestCLIRejectsOversizedInput(t *testing.T) {
	var out bytes.Buffer
	if err := run("../../examples/profiles", strings.NewReader(strings.Repeat("x", 65537)), &out); err == nil {
		t.Fatal("unbounded input")
	}
}
func TestCLIForcesShadowForActiveProfile(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile("../../examples/profiles/diagnostic.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("SHADOW_MODE"), []byte("ACTIVE_FREEZE_MODE"))
	if err = os.WriteFile(filepath.Join(dir, "p.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = run(dir, bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ACTIVE_FREEZE_MODE") || strings.Contains(out.String(), `"candidate":`) {
		t.Fatal(out.String())
	}
}
