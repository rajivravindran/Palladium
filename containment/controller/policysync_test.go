package controller

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"river3.local/containment/apiclient"
	"river3.local/containment/journal"
	policy "river3.local/policy"
)

func rawProfile(t *testing.T, p policy.Profile) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fakeAPI) setBundle(rev string, profiles ...json.RawMessage) {
	f.mu.Lock()
	f.bundle = apiclient.PolicyBundle{Revision: rev, Profiles: profiles}
	f.mu.Unlock()
}

func (f *fakeAPI) lastReport(t *testing.T) apiclient.PolicyReport {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		t.Fatal("no policy report sent")
	}
	return f.reports[len(f.reports)-1]
}

const (
	revA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestPolicySyncSwapsInConsoleEdits(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "policy.json")
	r := newRig(t, func(_ *rig, c *Config) { c.PolicyCache = cache })

	// Files say active: a decoy open pauses the worker.
	mustState(t, r.handle(r.event("ps-1", "file_open", decoyOpen("ps-1"), "success")), journal.Verified)
	if err := r.mock.Resume(context.Background(), cidWorker); err != nil {
		t.Fatal(err)
	}

	// An admin switches the worker to shadow in the console.
	shadow := activeProfile()
	shadow.Mode = policy.Shadow
	shadow.Version = 2
	r.api.setBundle(revA, rawProfile(t, shadow), rawProfile(t, sharedProfile()))
	if err := r.c.SyncPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.c.Policy(); got.Revision != revA || got.Profiles["diagnostic-worker"].Mode != policy.Shadow {
		t.Fatalf("policy not swapped: %+v", got)
	}
	out := r.handle(r.event("ps-2", "file_open", decoyOpen("ps-2"), "success"))
	if out.Candidate || out.Response != nil {
		t.Fatalf("shadow profile must not act: %+v", out)
	}
	if rep := r.api.lastReport(t); rep.ActiveRevision != revA || rep.SeenRevision != revA || rep.Error != "" || rep.Profiles != 2 {
		t.Fatalf("report %+v", rep)
	}
	if b, err := LoadPolicyCache(cache); err != nil || b.Revision != revA || len(b.Profiles) != 2 {
		t.Fatalf("cache %+v %v", b, err)
	}
}

func TestPolicySyncKeepsLastGoodSet(t *testing.T) {
	r := newRig(t)
	good := r.c.Policy()

	cases := map[string][]json.RawMessage{
		// payment-service is still assigned to payments-01 in the registry
		"workload payments-01 is assigned profile": {rawProfile(t, activeProfile())},
		"unknown field": {json.RawMessage(`{"name":"diagnostic-worker","kind":"ai_worker","surprise":1}`), rawProfile(t, sharedProfile())},
		// The stable prefix only: the engine's explanation after it changes with its rules.
		`invalid egress rule "nope"`: {json.RawMessage(`{"name":"diagnostic-worker","kind":"ai_worker","egress_allowed":["nope"]}`), rawProfile(t, sharedProfile())},
		"no profiles found":          {},
	}
	for want, profiles := range cases {
		r.api.setBundle(revB, profiles...)
		r.c.seenRev = "" // each case is a new revision as far as the controller knows
		if err := r.c.SyncPolicy(context.Background()); err != nil {
			t.Fatal(err)
		}
		if r.c.Policy() != good {
			t.Fatalf("%s: a bad set replaced the good one", want)
		}
		if rep := r.api.lastReport(t); !strings.Contains(rep.Error, want) || rep.SeenRevision != revB || rep.ActiveRevision != "" {
			t.Fatalf("%s: report %+v", want, rep)
		}
	}

	// The API being down never drops the policy either.
	r.api.mu.Lock()
	r.api.down = true
	r.api.mu.Unlock()
	if err := r.c.SyncPolicy(context.Background()); err == nil {
		t.Fatal("expected a fetch error")
	}
	if r.c.Policy() != good {
		t.Fatal("policy dropped while the API was down")
	}
}

func TestPolicySyncAbortsActionAcrossVersionChange(t *testing.T) {
	r := newRig(t)
	next := activeProfile()
	next.Version = 2
	p, err := BuildPolicy([]policy.Document{{Source: "a", Data: rawProfile(t, next)}, {Source: "b", Data: rawProfile(t, sharedProfile())}}, revA, r.reg)
	if err != nil {
		t.Fatal(err)
	}
	// Inspect #1 is the evaluation; #2 is the refresh before Revalidate. An admin's edit
	// landing in between must stop the action: it was decided under a policy no longer in force.
	r.mock.InspectHook = func(call int) {
		if call == 2 {
			r.c.SetPolicy(p)
		}
	}
	out := r.handle(r.event("ps-3", "file_open", decoyOpen("ps-3"), "success"))
	if !out.Candidate {
		t.Fatalf("expected a candidate from the first evaluation: %+v", out)
	}
	mustState(t, out, journal.Aborted)
	if len(r.mock.Calls()) != 0 {
		t.Fatal("adapter called after the policy changed")
	}
}

func TestBuildPolicyMatchesFileLoader(t *testing.T) {
	files, err := policy.LoadProfiles(filepath.Join("..", "fixtures", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []policy.Document
	for _, p := range files {
		docs = append(docs, policy.Document{Source: p.Name, Data: rawProfile(t, *p)})
	}
	p, err := BuildPolicy(docs, revA, fixtureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, _ := json.Marshal(p.Profiles[name])
		exp, _ := json.Marshal(want)
		if string(got) != string(exp) {
			t.Fatalf("%s differs after a round trip:\n%s\n%s", name, got, exp)
		}
	}
}
