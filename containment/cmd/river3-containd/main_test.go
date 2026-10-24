package main

import (
	"strings"
	"testing"
	"time"
)

func sane() options {
	return options{poll: 5 * time.Second, flush: 10 * time.Second, profileSync: 10 * time.Second, registryRefresh: 10 * time.Second,
		sessionSync: 5 * time.Second, guardTimeout: 0, guardMinConfidence: 0.6, guardChannels: "A,B", egressRefresh: time.Minute, registryReload: 5 * time.Second}
}

// time.NewTicker panics on d <= 0; these flags used to reach it after start-up.
func TestValidateRefusesNonPositiveLoopIntervals(t *testing.T) {
	if err := validate(sane()); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	for _, tc := range []struct {
		flag string
		set  func(*options)
	}{
		{"-poll", func(o *options) { o.poll = 0 }},
		{"-flush", func(o *options) { o.flush = -time.Second }},
		{"-profile-sync", func(o *options) { o.profileSync = 0 }},
		{"-registry-refresh", func(o *options) { o.registryRefresh = 0 }},
		{"-session-sync", func(o *options) { o.sessionSync = 0 }},
		{"-guard-timeout", func(o *options) { o.guardTimeout = -time.Second }},
		{"-registry-reload", func(o *options) { o.registryReload = -time.Second }},
		{"-sensor-heartbeat", func(o *options) { o.heartbeat = -1 }},
		{"-egress-refresh", func(o *options) { o.egressRefresh = -1 }},
	} {
		o := sane()
		tc.set(&o)
		err := validate(o)
		if err == nil || !strings.Contains(err.Error(), tc.flag) {
			t.Errorf("%s: got %v", tc.flag, err)
		}
	}
	// "0 = off" intervals are accepted at zero; -guard-timeout 0 is the mode default.
	o := sane()
	o.heartbeat, o.egressRefresh, o.registryReload, o.guardTimeout = 0, 0, 0, 0
	if err := validate(o); err != nil {
		t.Fatalf("zero means off: %v", err)
	}
}

func TestValidateGuardFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*options)
		want string // "" = accepted
	}{
		{"off", func(o *options) { o.guard = "off" }, ""},
		{"empty", func(o *options) { o.guard = "" }, ""},
		{"laya", func(o *options) { o.guard = "laya" }, ""},
		{"llm", func(o *options) { o.guard = "llm" }, ""},
		{"unknown mode", func(o *options) { o.guard = "ollama" }, "-guard"},
		{"laya conf 0", func(o *options) { o.guard = "laya"; o.guardMinConfidence = 0 }, "-guard-min-confidence"},
		{"laya conf 1.0", func(o *options) { o.guard = "laya"; o.guardMinConfidence = 1 }, ""},
		{"laya conf 1.01", func(o *options) { o.guard = "laya"; o.guardMinConfidence = 1.01 }, "-guard-min-confidence"},
		{"laya conf negative", func(o *options) { o.guard = "laya"; o.guardMinConfidence = -0.5 }, "-guard-min-confidence"},
		{"llm ignores conf", func(o *options) { o.guard = "llm"; o.guardMinConfidence = 7 }, ""},
		{"channels A", func(o *options) { o.guard = "laya"; o.guardChannels = "a" }, ""},
		{"channels bogus", func(o *options) { o.guard = "laya"; o.guardChannels = "A,C" }, "-guard-channels"},
		{"channels ignored when off", func(o *options) { o.guard = "off"; o.guardChannels = "zzz" }, ""},
	} {
		o := sane()
		tc.set(&o)
		err := validate(o)
		if tc.want == "" && err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want error naming %s", tc.name, err, tc.want)
		}
	}
}

func TestGuardTimeoutDefaultsPerMode(t *testing.T) {
	o := sane()
	o.guard = "laya"
	if got := guardTimeout(o); got != 3*time.Second {
		t.Fatalf("laya default %s", got)
	}
	o.guard = "llm"
	if got := guardTimeout(o); got != 8*time.Second {
		t.Fatalf("llm default %s", got)
	}
	o.guardTimeout = 1500 * time.Millisecond
	if got := guardTimeout(o); got != 1500*time.Millisecond {
		t.Fatalf("explicit flag ignored: %s", got)
	}
}
