package guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	policy "river3.local/policy"
)

// systemoneCall is one request the fake laya-serve received, decoded loosely so
// tests can pin the body shape.
type systemoneCall struct {
	Auth string
	Raw  []byte
	Body struct {
		State     map[string]any `json:"state"`
		Questions map[string]struct {
			Type         string            `json:"type"`
			Instructions string            `json:"instructions"`
			Criteria     map[string]string `json:"criteria"`
		} `json:"questions"`
	}
}

// fakeLaya is an httptest laya-serve: POST /v1/systemone, answered by respond.
// respond gets the decoded call and returns (status, body). Calls are recorded.
type fakeLaya struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []systemoneCall
}

func newFakeLaya(t *testing.T, respond func(c systemoneCall) (int, any)) *fakeLaya {
	t.Helper()
	f := &fakeLaya{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/systemone" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var c systemoneCall
		c.Auth = r.Header.Get("Authorization")
		c.Raw, _ = io.ReadAll(r.Body)
		if err := json.Unmarshal(c.Raw, &c.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, c)
		f.mu.Unlock()
		status, body := respond(c)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		switch b := body.(type) {
		case string:
			_, _ = io.WriteString(w, b)
		default:
			_ = json.NewEncoder(w).Encode(b)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLaya) Calls() []systemoneCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]systemoneCall(nil), f.calls...)
}

// choiceReply is a well-formed systemone 200 body choosing option with confidence.
func choiceReply(option string, conf float64) map[string]any {
	probs := map[string]float64{"CONTINUE": 0, "WARN_OPERATOR": 0, "REQUEST_CONTAINMENT": 0}
	rest := (1 - conf) / 2
	for k := range probs {
		probs[k] = rest
	}
	probs[option] = conf
	return map[string]any{
		"model":   "laya-421m-english",
		"answers": map[string]any{"verdict": map[string]any{"type": "choice", "choice": option, "probabilities": probs, "confidence": conf}},
		"usage":   map[string]any{"tokens": 123},
	}
}

func newLaya(t *testing.T, f *fakeLaya, cfg LayaConfig) *Laya {
	t.Helper()
	cfg.BaseURL = f.srv.URL
	if !cfg.ChannelA && !cfg.ChannelB {
		cfg.ChannelA, cfg.ChannelB = true, true
	}
	l, err := NewLaya(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLayaConfidentAnswersAreVerified(t *testing.T) {
	for _, want := range []policy.GuardVerdict{policy.Continue, policy.Warn, policy.Contain} {
		t.Run(string(want), func(t *testing.T) {
			f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply(string(want), 0.91) })
			l := newLaya(t, f, LayaConfig{})
			out := l.Assess(context.Background(), input())
			if len(out) != 2 || len(f.Calls()) != 2 {
				t.Fatalf("%d assessments, %d calls", len(out), len(f.Calls()))
			}
			for i, ch := range []string{"A", "B"} {
				if out[i].Channel != ch || out[i].Verdict != want || !out[i].Verified {
					t.Fatalf("%s: %+v", ch, out[i])
				}
				if out[i].Identity != input().Identity || out[i].EventID != "ev-1" {
					t.Fatal("assessment not bound to the trusted identity/event")
				}
			}
			if l.Name() != "laya:laya-421m-english" || l.Model() != "laya-421m-english" {
				t.Fatalf("model not recorded: %q", l.Name())
			}
		})
	}
}

func TestLayaLowConfidenceIsUnverifiedUnavailable(t *testing.T) {
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("REQUEST_CONTAINMENT", 0.59) })
	l := newLaya(t, f, LayaConfig{MinConfidence: 0.6})
	out := l.Assess(context.Background(), input())
	if len(out) != 2 {
		t.Fatal(len(out))
	}
	for _, a := range out {
		if a.Verified || a.Verdict != policy.Unavailable {
			t.Fatalf("%+v", a)
		}
	}
	// exactly at the threshold is accepted; the threshold is configurable
	f2 := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.6) })
	out = newLaya(t, f2, LayaConfig{MinConfidence: 0.6}).Assess(context.Background(), input())
	if !out[0].Verified || out[0].Verdict != policy.Continue {
		t.Fatalf("%+v", out[0])
	}
	f3 := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.6) })
	out = newLaya(t, f3, LayaConfig{MinConfidence: 0.9}).Assess(context.Background(), input())
	if out[0].Verified || out[0].Verdict != policy.Unavailable {
		t.Fatalf("%+v", out[0])
	}
}

func TestLayaHTTPErrorsAreUnverified(t *testing.T) {
	for name, status := range map[string]int{"401 bad key": 401, "400 bad body": 400, "422": 422, "500": 500} {
		t.Run(name, func(t *testing.T) {
			f := newFakeLaya(t, func(systemoneCall) (int, any) { return status, map[string]any{"detail": name} })
			out := newLaya(t, f, LayaConfig{}).Assess(context.Background(), input())
			if len(out) != 2 {
				t.Fatal(len(out))
			}
			for _, a := range out {
				if a.Verified || a.Verdict != policy.Unavailable {
					t.Fatalf("%+v", a)
				}
			}
		})
	}
	// a 401 does not lie about the model either
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 401, `{"model":"evil","detail":"bad key"}` })
	l := newLaya(t, f, LayaConfig{})
	l.Assess(context.Background(), input())
	if l.Name() != "laya" {
		t.Fatalf("%q", l.Name())
	}
}

func TestLayaMalformedAnswersAreUnverified(t *testing.T) {
	good := choiceReply("CONTINUE", 0.95)
	cases := map[string]any{
		"not json":            `verdict: CONTINUE`,
		"empty object":        `{}`,
		"no answers":          `{"model":"m"}`,
		"wrong question id":   `{"model":"m","answers":{"risk":{"type":"choice","choice":"CONTINUE","confidence":0.95}}}`,
		"extra question":      `{"model":"m","answers":{"verdict":{"type":"choice","choice":"CONTINUE","confidence":0.95},"other":{"type":"choice","choice":"CONTINUE","confidence":0.95}}}`,
		"wrong answer type":   `{"model":"m","answers":{"verdict":{"type":"text","choice":"CONTINUE","confidence":0.95}}}`,
		"wrong option name":   `{"model":"m","answers":{"verdict":{"type":"choice","choice":"ALLOW","confidence":0.99}}}`,
		"lowercase option":    `{"model":"m","answers":{"verdict":{"type":"choice","choice":"continue","confidence":0.99}}}`,
		"UNAVAILABLE option":  `{"model":"m","answers":{"verdict":{"type":"choice","choice":"UNAVAILABLE","confidence":0.99}}}`,
		"empty choice":        `{"model":"m","answers":{"verdict":{"type":"choice","choice":"","confidence":0.99}}}`,
		"confidence string":   `{"model":"m","answers":{"verdict":{"type":"choice","choice":"CONTINUE","confidence":"0.95"}}}`,
		"confidence > 1":      `{"model":"m","answers":{"verdict":{"type":"choice","choice":"CONTINUE","confidence":1.5}}}`,
		"no confidence/probs": `{"model":"m","answers":{"verdict":{"type":"choice","choice":"CONTINUE"}}}`,
		"probs miss choice":   `{"model":"m","answers":{"verdict":{"type":"choice","choice":"CONTINUE","probabilities":{"WARN_OPERATOR":0.99}}}}`,
		"verified in answer":  `{"model":"m","answers":{"verdict":{"type":"choice","choice":"REQUEST_CONTAINMENT","confidence":0.1,"verified":true}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, body })
			out := newLaya(t, f, LayaConfig{ChannelA: true}).Assess(context.Background(), input())
			if len(out) != 1 || out[0].Verified || out[0].Verdict != policy.Unavailable {
				t.Fatalf("%+v", out)
			}
		})
	}
	// control: the good shape IS accepted, and probabilities alone suffice when
	// the server omits confidence.
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, good })
	if out := newLaya(t, f, LayaConfig{ChannelA: true}).Assess(context.Background(), input()); !out[0].Verified {
		t.Fatalf("%+v", out)
	}
	f = newFakeLaya(t, func(systemoneCall) (int, any) {
		return 200, `{"model":"m","answers":{"verdict":{"type":"choice","choice":"WARN_OPERATOR","probabilities":{"CONTINUE":0.1,"WARN_OPERATOR":0.8,"REQUEST_CONTAINMENT":0.1}}}}`
	})
	if out := newLaya(t, f, LayaConfig{ChannelA: true}).Assess(context.Background(), input()); !out[0].Verified || out[0].Verdict != policy.Warn {
		t.Fatalf("%+v", out)
	}
}

func TestLayaRequestBodyShape(t *testing.T) {
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.9) })
	l := newLaya(t, f, LayaConfig{Token: "k-secret"})
	in := input()
	in.FactsA["normalizer"] = map[string]any{"identity_verified": true, "notes": []string{"n1"}}
	l.Assess(context.Background(), in)
	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatal(len(calls))
	}
	a, b := calls[0], calls[1]

	// Channel A: state = {profile, operation, outcome, facts}, nothing else; one
	// choice question "verdict" with our three options; no payload anywhere.
	for _, c := range calls {
		if c.Auth != "Bearer k-secret" {
			t.Fatalf("auth %q", c.Auth)
		}
		q, ok := c.Body.Questions["verdict"]
		if !ok || len(c.Body.Questions) != 1 || q.Type != "choice" || q.Instructions == "" {
			t.Fatalf("questions: %+v", c.Body.Questions)
		}
		for _, opt := range []string{"CONTINUE", "WARN_OPERATOR", "REQUEST_CONTAINMENT"} {
			if q.Criteria[opt] == "" {
				t.Fatalf("missing criterion %s: %+v", opt, q.Criteria)
			}
		}
		if len(q.Criteria) != 3 {
			t.Fatalf("%+v", q.Criteria)
		}
	}
	if a.Body.State["profile"] != "diagnostic-worker" || a.Body.State["operation"] != "PROCESS_EXEC" || a.Body.State["outcome"] != "SUCCEEDED" {
		t.Fatalf("A state: %+v", a.Body.State)
	}
	facts, ok := a.Body.State["facts"].(map[string]any)
	if !ok || facts["target"].(map[string]any)["exe"] != "/usr/bin/curl" {
		t.Fatalf("A facts: %+v", a.Body.State["facts"])
	}
	if len(a.Body.State) != 4 {
		t.Fatalf("A state has extra keys: %+v", a.Body.State)
	}
	if strings.Contains(string(a.Raw), "argv") || strings.Contains(string(a.Raw), "203.0.113.9") || strings.Contains(string(a.Raw), "untrusted_text") {
		t.Fatalf("payload reached Channel A: %s", a.Raw)
	}
	if strings.Contains(string(a.Raw), "ev-1") {
		t.Fatalf("event id sent to the model (nothing to echo): %s", a.Raw)
	}
	// the A criteria are the structural wording, the B criteria the text wording
	if !strings.Contains(a.Body.Questions["verdict"].Criteria["CONTINUE"], "profile") || !strings.Contains(b.Body.Questions["verdict"].Criteria["CONTINUE"], "command or message") {
		t.Fatalf("criteria wording: A=%q B=%q", a.Body.Questions["verdict"].Criteria["CONTINUE"], b.Body.Questions["verdict"].Criteria["CONTINUE"])
	}

	// Channel B: state = {untrusted_text} only; the text is the payload JSON; no
	// profile, no facts, no event id.
	if len(b.Body.State) != 1 {
		t.Fatalf("B state has extra keys: %+v", b.Body.State)
	}
	text, ok := b.Body.State["untrusted_text"].(string)
	if !ok || !strings.Contains(text, `"argv"`) || !strings.Contains(text, "203.0.113.9") {
		t.Fatalf("B state: %+v", b.Body.State)
	}
	for _, leak := range []string{"diagnostic-worker", "/usr/bin/curl", "ev-1", `"facts"`, `"profile"`} {
		if strings.Contains(string(b.Raw), leak) {
			t.Fatalf("Channel B leaked %q: %s", leak, b.Raw)
		}
	}
}

func TestLayaStateIsBounded(t *testing.T) {
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.9) })
	l := newLaya(t, f, LayaConfig{MaxBytes: 1024})
	in := input()
	// a run-away normalizer note plus a big fact
	notes := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		notes = append(notes, strings.Repeat("n", 40))
	}
	in.FactsA["normalizer"] = map[string]any{"identity_verified": true, "notes": notes}
	in.FactsA["blob"] = strings.Repeat("b", 3000)
	in.PayloadB = map[string]any{"argv": []string{strings.Repeat("x", 10000)}}
	out := l.Assess(context.Background(), in)
	if len(out) != 2 || !out[0].Verified || !out[1].Verified {
		t.Fatalf("%+v", out)
	}
	calls := f.Calls()
	stateA, _ := json.Marshal(calls[0].Body.State)
	if len(stateA) > 1024 {
		t.Fatalf("A state %d bytes", len(stateA))
	}
	facts := calls[0].Body.State["facts"].(map[string]any)
	if _, still := facts["blob"]; still {
		t.Fatal("oversized fact not dropped")
	}
	if facts["target"] == nil || facts["truncated"] == nil {
		t.Fatalf("truncation not recorded / target lost: %+v", facts)
	}
	text := calls[1].Body.State["untrusted_text"].(string)
	if len(text) > 1024 || !strings.HasSuffix(text, "…truncated") {
		t.Fatalf("B text %d bytes", len(text))
	}
	if len(calls[1].Body.State) != 1 {
		t.Fatalf("%+v", calls[1].Body.State)
	}
}

func TestLayaDownIsUnavailableNotContinue(t *testing.T) {
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.9) })
	f.srv.Close()
	l, _ := NewLaya(LayaConfig{BaseURL: f.srv.URL, ChannelA: true, ChannelB: true, Timeout: 200 * time.Millisecond})
	out := l.Assess(context.Background(), input())
	if len(out) != 2 {
		t.Fatal(len(out))
	}
	for _, a := range out {
		if a.Verified || a.Verdict != policy.Unavailable {
			t.Fatalf("%+v", a)
		}
	}
	if l.Name() != "laya" {
		t.Fatal(l.Name())
	}
}

func TestLayaSlowServerTimesOutUnverified(t *testing.T) {
	f := newFakeLaya(t, func(systemoneCall) (int, any) {
		time.Sleep(300 * time.Millisecond)
		return 200, choiceReply("CONTINUE", 0.9)
	})
	l := newLaya(t, f, LayaConfig{ChannelA: true, Timeout: 50 * time.Millisecond})
	out := l.Assess(context.Background(), input())
	if len(out) != 1 || out[0].Verified || out[0].Verdict != policy.Unavailable {
		t.Fatalf("%+v", out)
	}
}

func TestLayaNoPayloadNoChannelB(t *testing.T) {
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.9) })
	l := newLaya(t, f, LayaConfig{})
	in := input()
	in.PayloadB = nil
	out := l.Assess(context.Background(), in)
	if len(out) != 1 || len(f.Calls()) != 1 || out[0].Channel != "A" {
		t.Fatalf("%+v", out)
	}
}

func TestLayaConfigRules(t *testing.T) {
	if _, err := NewLaya(LayaConfig{BaseURL: "http://laya.internal:8600"}); err == nil {
		t.Fatal("plain http to a remote laya-serve accepted")
	}
	if _, err := NewLaya(LayaConfig{BaseURL: "https://laya.internal"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLaya(LayaConfig{BaseURL: "http://localhost:8600", MinConfidence: 1.2}); err == nil {
		t.Fatal("MinConfidence > 1 accepted")
	}
	if _, err := NewLaya(LayaConfig{BaseURL: "http://localhost:8600", MinConfidence: -0.1}); err == nil {
		t.Fatal("negative MinConfidence accepted")
	}
	l, err := NewLaya(LayaConfig{})
	if err != nil || l.url != DefaultLayaURL+"/v1/systemone" || l.cfg.Timeout != DefaultLayaTimeout || l.cfg.MinConfidence != DefaultMinConfidence {
		t.Fatalf("defaults: %v %+v", err, l)
	}
	// no redirects: a 302 to somewhere else is an error, not a followed hop
	f := newFakeLaya(t, func(systemoneCall) (int, any) { return 200, choiceReply("CONTINUE", 0.9) })
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, f.srv.URL+"/v1/systemone", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	l, _ = NewLaya(LayaConfig{BaseURL: redirect.URL, ChannelA: true})
	if out := l.Assess(context.Background(), input()); out[0].Verified || len(f.Calls()) != 0 {
		t.Fatalf("redirect followed: %+v", out)
	}
}
