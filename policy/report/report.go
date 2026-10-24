// Package report sends policy decisions to the River3 API as incidents.
//
// It only reports: it never executes or authorizes a response. A decision's Action is
// stored as evidence ("eligible candidate at most"); results come from the containment layer.
//
// Noise control: IN_SCOPE decisions are never posted. UNKNOWN decisions are counted
// as visibility gaps and only posted when Config.ReportUnknown is set, because
// without a trusted context provider every event is UNKNOWN.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	policy "river3.local/policy"
)

type Config struct {
	BaseURL       string        // e.g. https://river3.internal (http allowed only for loopback)
	Token         string        // machine token whose role includes incidents.write (role "policy")
	Client        *http.Client  // optional; default has a 10 s timeout and no redirects
	ReportUnknown bool          // post UNKNOWN decisions too (default: count only)
	MaxAttempts   int           // default 4
	Backoff       time.Duration // first retry delay, doubled each time; default 200 ms
}

type Stats struct {
	Posted, Duplicates, SkippedInScope, SkippedUnknown, Failed uint64
}

type Reporter struct {
	cfg   Config
	base  *url.URL
	mu    sync.Mutex
	stats Stats
}

// Workload mirrors the API's workload enrollment.
type Workload struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Kind    string `json:"kind"`
	Sensor  string `json:"sensor,omitempty"`
}

type Result string

const (
	Posted     Result = "posted"
	Duplicate  Result = "duplicate" // the API already has this evidence: treated as success
	SkipScope  Result = "skipped_in_scope"
	SkipUnknwn Result = "skipped_unknown"
)

// APIError is a non-retryable rejection (4xx other than 409/429).
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string { return fmt.Sprintf("river3 api: %d %s", e.Status, e.Detail) }

func New(cfg Config) (*Reporter, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("report: BaseURL must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("report: plain http is only allowed for localhost; use https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("report: BaseURL must not carry credentials, query or fragment")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("report: token is required")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: 10 * time.Second,
			// Never forward the bearer token to wherever a redirect points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 4
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 200 * time.Millisecond
	}
	return &Reporter{cfg: cfg, base: u}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (r *Reporter) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *Reporter) count(f func(*Stats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

// EnsureWorkload enrolls or updates the workload the incidents will reference.
func (r *Reporter) EnsureWorkload(ctx context.Context, w Workload) error {
	if w.Sensor == "" {
		w.Sensor = "policy-engine"
	}
	_, err := r.post(ctx, "/api/v1/workloads", w)
	return err
}

// Report posts one decision. profileKind is the profile's kind (ai_worker | shared_service).
func (r *Reporter) Report(ctx context.Context, ev policy.Event, d policy.Decision, profileKind string) (Result, error) {
	switch d.Status {
	case policy.InScope:
		r.count(func(s *Stats) { s.SkippedInScope++ })
		return SkipScope, nil
	case policy.Unknown:
		if !r.cfg.ReportUnknown {
			r.count(func(s *Stats) { s.SkippedUnknown++ })
			return SkipUnknwn, nil
		}
	}
	status, err := r.post(ctx, "/api/v1/incidents", BuildIncident(ev, d, profileKind))
	if err != nil {
		r.count(func(s *Stats) { s.Failed++ })
		return "", err
	}
	if status == http.StatusConflict {
		r.count(func(s *Stats) { s.Duplicates++ })
		return Duplicate, nil
	}
	r.count(func(s *Stats) { s.Posted++ })
	return Posted, nil
}

// post returns the final HTTP status. 2xx and 409 are success; 429/5xx/network errors retry.
func (r *Reporter) post(ctx context.Context, path string, body any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	endpoint := r.base.JoinPath(path).String()
	delay := r.cfg.Backoff
	var last error
	for attempt := 1; attempt <= r.cfg.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
		resp, err := r.cfg.Client.Do(req)
		if err == nil {
			detail := readDetail(resp.Body)
			resp.Body.Close()
			switch {
			case resp.StatusCode < 300:
				return resp.StatusCode, nil
			case resp.StatusCode == http.StatusConflict:
				return resp.StatusCode, nil
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				last = &APIError{resp.StatusCode, detail}
			default:
				return resp.StatusCode, &APIError{resp.StatusCode, detail}
			}
		} else {
			last = err
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return 0, err
			}
		}
		if attempt < r.cfg.MaxAttempts {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
	}
	return 0, fmt.Errorf("report: giving up after %d attempts: %w", r.cfg.MaxAttempts, last)
}

func readDetail(body io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(body, 4096))
	var parsed struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(b, &parsed) == nil && parsed.Detail != nil {
		return fmt.Sprint(parsed.Detail)
	}
	return strings.TrimSpace(string(b))
}
