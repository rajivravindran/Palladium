package main

// Where events go. Several sinks can run at once.
//
//   stdout      JSONL, one Event per line (debugging, replay fixtures)
//   controller  POST each Event to river3-containd /v1/events (sensor token) — this is
//               "to the engine": the controller normalizes, evaluates and may contain
//   api         batch POST /api/v1/events to the River3 hub (ingest token) for the
//               operator console's event history
//
// Sinks never block the ring-buffer reader: each has a bounded queue and drops
// (counted) when the receiver is slower than the kernel.

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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Sink interface {
	Name() string
	Emit(ev Event)           // non-blocking
	Run(ctx context.Context) // delivery loop; returns when ctx ends
	Stats() SinkStats
}

type SinkStats struct {
	Sent, Dropped, Failed, Duplicates uint64
}

// ---------------------------------------------------------------- stdout

type stdoutSink struct {
	mu    sync.Mutex
	w     io.Writer
	stats SinkStats
}

func newStdoutSink(w io.Writer) *stdoutSink {
	if w == nil {
		w = os.Stdout
	}
	return &stdoutSink{w: w}
}

func (s *stdoutSink) Name() string { return "stdout" }
func (s *stdoutSink) Emit(ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		s.stats.Failed++
		return
	}
	s.stats.Sent++
}
func (s *stdoutSink) Run(ctx context.Context) { <-ctx.Done() }
func (s *stdoutSink) Stats() SinkStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// ---------------------------------------------------------------- HTTP plumbing

type apiClient struct {
	base   *url.URL
	token  string
	client *http.Client
}

func newAPIClient(baseURL, token string) (*apiClient, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%q: must be an absolute http(s) URL", baseURL)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("%q: plain http is only allowed for localhost", baseURL)
	}
	if u.User != nil || u.RawQuery != "" {
		return nil, fmt.Errorf("%q: URL must not carry credentials or a query", baseURL)
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("%s: a bearer token is required", u.Host)
	}
	return &apiClient{base: u, token: token, client: &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type httpStatusError struct {
	code   int
	detail string
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d %s", e.code, e.detail) }

func (c *apiClient) post(ctx context.Context, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		var parsed struct {
			Detail any `json:"detail"`
		}
		detail := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &parsed) == nil && parsed.Detail != nil {
			detail = fmt.Sprint(parsed.Detail)
		}
		return &httpStatusError{resp.StatusCode, detail}
	}
	return nil
}

// ---------------------------------------------------------------- controller sink

type controllerSink struct {
	api                         *apiClient
	queue                       chan Event
	sent, dropped, failed, dups atomic.Uint64
}

func newControllerSink(baseURL, sensorToken string, depth int) (*controllerSink, error) {
	api, err := newAPIClient(baseURL, sensorToken)
	if err != nil {
		return nil, fmt.Errorf("controller sink: %w", err)
	}
	if depth <= 0 {
		depth = 4096
	}
	return &controllerSink{api: api, queue: make(chan Event, depth)}, nil
}

func (s *controllerSink) Name() string { return "controller" }
func (s *controllerSink) Emit(ev Event) {
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
	}
}

func (s *controllerSink) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			s.deliver(ctx, ev)
		}
	}
}

func (s *controllerSink) deliver(ctx context.Context, ev Event) {
	delay := 200 * time.Millisecond
	for attempt := 1; attempt <= 4; attempt++ {
		err := s.api.post(ctx, "/v1/events", ev)
		var he *httpStatusError
		switch {
		case err == nil:
			s.sent.Add(1)
			return
		case errors.As(err, &he) && he.code < 500 && he.code != 429:
			// 401/422: our fault or our token; retrying will not help.
			s.failed.Add(1)
			logf("controller: event %s rejected: %v", ev.Facts.ID, err)
			return
		case errors.Is(err, context.Canceled):
			return
		}
		if attempt == 4 {
			s.failed.Add(1)
			logf("controller: event %s undelivered: %v", ev.Facts.ID, err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
	}
}

func (s *controllerSink) Stats() SinkStats {
	return SinkStats{Sent: s.sent.Load(), Dropped: s.dropped.Load(), Failed: s.failed.Load(), Duplicates: s.dups.Load()}
}

// ---------------------------------------------------------------- API (hub) sink

// apiEvent is the hub's EventIn shape (api/river3_api/schemas.py).
type apiEvent struct {
	ID         string         `json:"id"`
	WorkloadID string         `json:"workload_id"`
	Kind       Kind           `json:"kind"`
	Outcome    Outcome        `json:"outcome"`
	TS         time.Time      `json:"ts"`
	Facts      map[string]any `json:"facts"`
	Payload    map[string]any `json:"payload"`
}

func toAPIEvent(ev Event) apiEvent {
	facts := map[string]any{}
	b, _ := json.Marshal(ev.Facts)
	_ = json.Unmarshal(b, &facts)
	payload := map[string]any{}
	if len(ev.Payload.Argv) > 0 {
		payload["argv"] = ev.Payload.Argv
	}
	ts := time.Unix(0, int64(ev.Facts.Received)).UTC()
	if ev.Facts.Received == 0 {
		ts = time.Now().UTC()
	}
	return apiEvent{ID: ev.Facts.ID, WorkloadID: ev.Facts.Workload.ID, Kind: ev.Facts.Kind, Outcome: ev.Facts.Outcome,
		TS: ts, Facts: facts, Payload: payload}
}

type apiSink struct {
	api                         *apiClient
	queue                       chan Event
	batch                       int
	flushWait                   time.Duration
	sent, dropped, failed, dups atomic.Uint64
}

func newAPISink(baseURL, ingestToken string, depth, batch int, flushWait time.Duration) (*apiSink, error) {
	api, err := newAPIClient(baseURL, ingestToken)
	if err != nil {
		return nil, fmt.Errorf("api sink: %w", err)
	}
	if depth <= 0 {
		depth = 8192
	}
	if batch <= 0 || batch > 1000 {
		batch = 200
	}
	if flushWait <= 0 {
		flushWait = time.Second
	}
	return &apiSink{api: api, queue: make(chan Event, depth), batch: batch, flushWait: flushWait}, nil
}

func (s *apiSink) Name() string { return "api" }
func (s *apiSink) Emit(ev Event) {
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
	}
}

func (s *apiSink) Run(ctx context.Context) {
	t := time.NewTicker(s.flushWait)
	defer t.Stop()
	var pending []apiEvent
	flush := func() {
		if len(pending) == 0 {
			return
		}
		s.send(ctx, pending)
		pending = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			pending = append(pending, toAPIEvent(ev))
			if len(pending) >= s.batch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (s *apiSink) send(ctx context.Context, batch []apiEvent) {
	err := s.api.post(ctx, "/api/v1/events", batch)
	var he *httpStatusError
	switch {
	case err == nil:
		s.sent.Add(uint64(len(batch)))
	case errors.As(err, &he) && he.code == http.StatusConflict && len(batch) > 1:
		// One duplicate poisons the whole batch (the API is all-or-nothing): resend one by one.
		for _, e := range batch {
			s.send(ctx, []apiEvent{e})
		}
	case errors.As(err, &he) && he.code == http.StatusConflict:
		s.dups.Add(1)
	default:
		s.failed.Add(uint64(len(batch)))
		logf("api: %d event(s) undelivered: %v", len(batch), err)
	}
}

func (s *apiSink) Stats() SinkStats {
	return SinkStats{Sent: s.sent.Load(), Dropped: s.dropped.Load(), Failed: s.failed.Load(), Duplicates: s.dups.Load()}
}

// ---------------------------------------------------------------- fan-out

type fanout struct{ sinks []Sink }

func (f fanout) Emit(ev Event) {
	for _, s := range f.sinks {
		s.Emit(ev)
	}
}
