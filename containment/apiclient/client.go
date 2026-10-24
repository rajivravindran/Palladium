// Package apiclient talks to the River3 API with machine tokens.
//
// Controller → API:  POST /api/v1/workloads, POST /api/v1/incidents   (role policy)
//
//	PATCH /api/v1/incidents/{id}/response             (role containment)
//	POST /api/v1/actions/{id}/result                  (role containment)
//
// API → controller:  GET /api/v1/actions                               (role containment)
//
//	GET /api/v1/policy/bundle, POST /api/v1/policy/sync (role policy; -profiles-from-api)
//
// Rules mirrored from policy/report: https only (plain http just for loopback),
// no redirects (the bearer token must never follow one), bounded retries on
// 429/5xx/network errors, and 4xx returned as a typed non-retryable error.
package apiclient

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
	"time"
)

type Config struct {
	BaseURL          string
	ContainmentToken string // role containment
	PolicyToken      string // role policy; empty means "same as ContainmentToken" (custom combined role)
	Client           *http.Client
	MaxAttempts      int
	Backoff          time.Duration
}

type Client struct {
	cfg  Config
	base *url.URL
}

// APIError is a non-retryable rejection.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string { return fmt.Sprintf("river3 api: %d %s", e.Status, e.Detail) }

// IsStatus reports whether err is an APIError with the given status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("apiclient: BaseURL must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("apiclient: plain http is only allowed for localhost; use https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("apiclient: BaseURL must not carry credentials, query or fragment")
	}
	if strings.TrimSpace(cfg.ContainmentToken) == "" {
		return nil, fmt.Errorf("apiclient: containment token is required")
	}
	if cfg.PolicyToken == "" {
		cfg.PolicyToken = cfg.ContainmentToken
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 4
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 200 * time.Millisecond
	}
	return &Client{cfg: cfg, base: u}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) do(ctx context.Context, token, method, path string, q url.Values, body any, out any) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	u := c.base.JoinPath(path)
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	endpoint := u.String()
	delay := c.cfg.Backoff
	var last error
	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
		if err != nil {
			return 0, err
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.cfg.Client.Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			switch {
			case resp.StatusCode < 300:
				if out != nil && len(b) > 0 {
					if err := json.Unmarshal(b, out); err != nil {
						return resp.StatusCode, fmt.Errorf("apiclient: bad response body: %w", err)
					}
				}
				return resp.StatusCode, nil
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				last = &APIError{resp.StatusCode, detail(b)}
			default:
				return resp.StatusCode, &APIError{resp.StatusCode, detail(b)}
			}
		} else {
			last = err
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return 0, err
			}
		}
		if attempt < c.cfg.MaxAttempts {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
	}
	return 0, fmt.Errorf("apiclient: giving up after %d attempts: %w", c.cfg.MaxAttempts, last)
}

func detail(b []byte) string {
	var parsed struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(b, &parsed) == nil && parsed.Detail != nil {
		return fmt.Sprint(parsed.Detail)
	}
	return strings.TrimSpace(string(b))
}

// ---------------------------------------------------------------- wire types

type Workload struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Kind    string `json:"kind"`
	Sensor  string `json:"sensor,omitempty"`
	Team    string `json:"team,omitempty"` // CONTRACTS.md §6; sent only when the enrolment names one
}

// ResponseUpdate is the body of PATCH /incidents/{id}/response.
type ResponseUpdate struct {
	Response      map[string]any `json:"response"`
	Status        string         `json:"status,omitempty"`         // open|contained|resolved|false_positive
	WorkloadState string         `json:"workload_state,omitempty"` // running|frozen|terminated|unknown
}

// OperatorAction is one queued operator request (GET /actions, webhook body).
type OperatorAction struct {
	ID         string `json:"id"`
	IncidentID string `json:"incident_id"`
	WorkloadID string `json:"workload_id"`
	Action     string `json:"action"` // resume | terminate | revoke_session | resolve | false_positive
	// SessionID is the incident's bound session (CONTRACTS.md §2.2); the API copies it
	// from the incident, never from the operator. Empty when the incident has none.
	SessionID   string         `json:"session_id"`
	Operator    string         `json:"operator"`
	Reason      string         `json:"reason"`
	Status      string         `json:"status"`
	Result      map[string]any `json:"result"`
	RequestedAt string         `json:"requested_at"`
	CompletedAt *string        `json:"completed_at"`
}

// ActionResult is the body of POST /actions/{id}/result.
type ActionResult struct {
	Status        string         `json:"status"` // completed | failed
	Detail        map[string]any `json:"detail"`
	WorkloadState string         `json:"workload_state,omitempty"`
}

// ---------------------------------------------------------------- calls

func (c *Client) EnsureWorkload(ctx context.Context, w Workload) error {
	if w.Sensor == "" {
		w.Sensor = "river3-containd"
	}
	_, err := c.do(ctx, c.cfg.PolicyToken, http.MethodPost, "/api/v1/workloads", nil, w, nil)
	return err
}

// CreateIncident posts an incident and returns its id. A 409 (duplicate event id)
// is returned as an APIError so the caller can decide what it knows.
func (c *Client) CreateIncident(ctx context.Context, body any) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if _, err := c.do(ctx, c.cfg.PolicyToken, http.MethodPost, "/api/v1/incidents", nil, body, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("apiclient: incident created but no id returned")
	}
	return out.ID, nil
}

func (c *Client) PatchResponse(ctx context.Context, incidentID string, body ResponseUpdate) error {
	_, err := c.do(ctx, c.cfg.ContainmentToken, http.MethodPatch, "/api/v1/incidents/"+url.PathEscape(incidentID)+"/response", nil, body, nil)
	return err
}

// QueuedActions fetches operator requests in the given status (requested | delivered).
func (c *Client) QueuedActions(ctx context.Context, status string) ([]OperatorAction, error) {
	var out []OperatorAction
	_, err := c.do(ctx, c.cfg.ContainmentToken, http.MethodGet, "/api/v1/actions", url.Values{"status": {status}, "limit": {"200"}}, nil, &out)
	return out, err
}

func (c *Client) PostResult(ctx context.Context, actionID string, body ActionResult) error {
	_, err := c.do(ctx, c.cfg.ContainmentToken, http.MethodPost, "/api/v1/actions/"+url.PathEscape(actionID)+"/result", nil, body, nil)
	return err
}

// PolicyBundle is the complete profile set an admin maintains in the console.
// Profiles stay raw so the policy engine's strict decoder sees exactly what the API sent.
type PolicyBundle struct {
	Revision string            `json:"revision"`
	Profiles []json.RawMessage `json:"profiles"`
}

// PolicyReport tells the API which revision this controller saw and which it enforces.
type PolicyReport struct {
	SeenRevision   string `json:"seen_revision"`
	ActiveRevision string `json:"active_revision"`
	Profiles       int    `json:"profiles"`
	Error          string `json:"error,omitempty"`
}

func (c *Client) PolicyBundle(ctx context.Context) (PolicyBundle, error) {
	var out PolicyBundle
	_, err := c.do(ctx, c.cfg.PolicyToken, http.MethodGet, "/api/v1/policy/bundle", nil, nil, &out)
	return out, err
}

func (c *Client) ReportPolicy(ctx context.Context, r PolicyReport) error {
	_, err := c.do(ctx, c.cfg.PolicyToken, http.MethodPost, "/api/v1/policy/sync", nil, r, nil)
	return err
}

// Session is one row of GET /api/v1/sessions (CONTRACTS.md §1.1/§1.2) as the API
// serialises it (main.ser_session). Only the fields the controller uses are typed;
// the rest are tolerated, since this is a read of the API's own record.
type Session struct {
	ID         string  `json:"id"`
	WorkloadID string  `json:"workload_id"`
	Principal  string  `json:"principal"`
	State      string  `json:"state"` // active | ended | revoked
	StartedAt  string  `json:"started_at"`
	LastSeenAt *string `json:"last_seen_at"`
}

// sessionsPage is the API's page size (main.page: limit ≤ 500) and maxSessionPages
// bounds one sync; 5000 simultaneously active sessions on one node is already far
// beyond what a controller should see.
const (
	sessionsPage    = 500
	maxSessionPages = 10
)

// ActiveSessions lists every session the API currently holds as active, newest
// first, with the containment token (role containment gained sessions.read, §1.2).
func (c *Client) ActiveSessions(ctx context.Context) ([]Session, error) {
	var all []Session
	for page := 0; page < maxSessionPages; page++ {
		var out []Session
		q := url.Values{"state": {"active"}, "limit": {fmt.Sprint(sessionsPage)}, "offset": {fmt.Sprint(page * sessionsPage)}}
		if _, err := c.do(ctx, c.cfg.ContainmentToken, http.MethodGet, "/api/v1/sessions", q, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out...)
		if len(out) < sessionsPage {
			return all, nil
		}
	}
	return all, nil
}
