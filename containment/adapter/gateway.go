package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"river3.local/containment/sign"
	policy "river3.local/policy"
)

// Gateway is the session adapter for a customer's agent gateway (CONTRACTS.md §2.1,
// adapter name "gateway"). It is the only component that can end an agent run:
// the controller never talks to the agent, the model or the harness, only to the
// gateway that binds sessions to workloads.
//
// Trust: the gateway's replies are Channel B. What it says about a session's state
// decides VERIFIED / FAILED / UNKNOWN for a revoke, and which session was bound to a
// workload came from the same gateway through the API. Neither can create or remove
// a violation: that is decided from kernel facts before this adapter is ever called.
// A lying gateway can at most get the wrong session revoked, or report a revoke it
// did not perform, and both are visible in the journal as its own claims.
//
// Transport: https, or plain http only to loopback (a dev gateway on the node); no
// redirects (the signed body must not be re-sent somewhere else); keep-alives off;
// 10 s per call; reply bodies capped at 64 KiB. Every request carries the webhook
// signature scheme (package sign): X-River3-Timestamp / X-River3-Delivery /
// X-River3-Signature over "<ts>.<delivery>.<body>", so a gateway verifies the
// controller exactly as the controller verifies the API's webhook.
type Gateway struct {
	base    *url.URL
	secret  []byte
	client  *http.Client
	timeout time.Duration
	now     func() time.Time
	deliver func() string
}

// GatewayTimeout is the per-call budget. A gateway that does not answer in time
// yields an adapter error, which the controller settles by inspection (UNKNOWN when
// the inspection times out too).
const GatewayTimeout = 10 * time.Second

// MinGatewaySecret is the shortest RIVER3_GATEWAY_SECRET accepted (CONTRACTS.md §2.1: ≥32).
const MinGatewaySecret = 32

const maxGatewayReply = 64 << 10

var sessionIdent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// NewGateway builds the adapter. The URL is the gateway's base (paths /v1/sessions/...
// are appended); the secret is shared with the gateway out of band.
func NewGateway(rawURL string, secret []byte) (*Gateway, error) {
	u, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("gateway: -gateway-url must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("gateway: plain http is only allowed for localhost; use https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("gateway: URL must not carry credentials, query or fragment")
	}
	if len(secret) < MinGatewaySecret {
		return nil, fmt.Errorf("gateway: RIVER3_GATEWAY_SECRET must be at least %d characters", MinGatewaySecret)
	}
	tr := &http.Transport{DisableKeepAlives: true, Proxy: nil}
	return &Gateway{
		base:    u,
		secret:  append([]byte(nil), secret...),
		client:  &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: GatewayTimeout,
		now:     func() time.Time { return time.Now().UTC() },
		deliver: sign.NewDelivery,
	}, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (g *Gateway) Name() string             { return "gateway" }
func (g *Gateway) Actions() []policy.Action { return []policy.Action{policy.Revoke} }

// revokeRequest is the body of POST /v1/sessions/{id}/revoke (CONTRACTS.md §2.1).
type revokeRequest struct {
	Reason         string `json:"reason"`
	IncidentID     string `json:"incident_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

type stateReply struct {
	State     string `json:"state"`
	Principal string `json:"principal"`
	StartedAt string `json:"started_at"`
}

// Revoke posts the revoke request and returns the state the gateway claims. 200 and
// 202 are the accepted replies; 404 is ErrSessionUnknown; anything else is an error
// carrying the status. The controller treats the return value as a claim and
// inspects afterwards.
func (g *Gateway) Revoke(ctx context.Context, sessionID, reason, incidentID, idempotencyKey string) (SessionState, error) {
	if !sessionIdent.MatchString(sessionID) {
		return "", fmt.Errorf("gateway: refusing malformed session id")
	}
	body, err := json.Marshal(revokeRequest{Reason: reason, IncidentID: incidentID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return "", err
	}
	status, reply, err := g.do(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(sessionID)+"/revoke", body)
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusOK, http.StatusAccepted:
	case http.StatusNotFound:
		return SessionUnknown, ErrSessionUnknown
	default:
		return "", fmt.Errorf("gateway: revoke returned %d: %s", status, snippet(reply))
	}
	var r stateReply
	if err := policy.DecodeStrict(reply, &r); err != nil {
		return "", fmt.Errorf("gateway: malformed revoke reply: %w", err)
	}
	st, ok := parseSessionState(r.State, SessionRevoked, SessionActive, SessionUnknown)
	if !ok {
		return "", fmt.Errorf("gateway: revoke reply state %q is not revoked|active|unknown", r.State)
	}
	return st, nil
}

// InspectSession asks the gateway for the session's current state. 404 = unknown
// (a real inspected state, not an error). Any other non-200 or a malformed reply is
// an error, which the controller journals as UNKNOWN: no claim either way.
func (g *Gateway) InspectSession(ctx context.Context, sessionID string) (SessionInfo, error) {
	if !sessionIdent.MatchString(sessionID) {
		return SessionInfo{}, fmt.Errorf("gateway: refusing malformed session id")
	}
	status, reply, err := g.do(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(sessionID), nil)
	if err != nil {
		return SessionInfo{}, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return SessionInfo{ID: sessionID, State: SessionUnknown}, nil
	default:
		return SessionInfo{}, fmt.Errorf("gateway: inspect returned %d: %s", status, snippet(reply))
	}
	var r stateReply
	if err := policy.DecodeStrict(reply, &r); err != nil {
		return SessionInfo{}, fmt.Errorf("gateway: malformed session reply: %w", err)
	}
	st, ok := parseSessionState(r.State, SessionActive, SessionRevoked, SessionEnded, SessionUnknown)
	if !ok {
		return SessionInfo{}, fmt.Errorf("gateway: session state %q is not active|revoked|ended|unknown", r.State)
	}
	return SessionInfo{ID: sessionID, State: st, Principal: truncateStr(r.Principal, 128), StartedAt: truncateStr(r.StartedAt, 64)}, nil
}

func parseSessionState(s string, allowed ...SessionState) (SessionState, bool) {
	for _, a := range allowed {
		if SessionState(s) == a {
			return a, true
		}
	}
	return "", false
}

// do sends one signed request. The signature covers the exact bytes sent (an empty
// body for GET), a fresh delivery id and the current unix second.
func (g *Gateway) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	u := *g.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range sign.Headers(g.secret, body, g.now().Unix(), g.deliver()) {
		req.Header[k] = v
	}
	if body == nil {
		req.Header.Del("Content-Type")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("gateway: %w", err)
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxGatewayReply))
	return resp.StatusCode, reply, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
