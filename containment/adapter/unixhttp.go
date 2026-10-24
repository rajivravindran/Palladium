package adapter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// socketClient is the HTTP-over-unix-socket plumbing the Podman and Docker adapters
// share. The settings are deliberate for a containment path:
//
//   - one request per connection (keep-alives off): a daemon that hangs a pooled
//     connection must not stall the next pause;
//   - no redirects: the daemon never issues them, and following one would send the
//     request somewhere the operator did not configure;
//   - a hard per-call timeout on top of the caller's context, so a wedged runtime
//     yields UNKNOWN after 10 s instead of blocking the controller's action lock;
//   - response bodies capped at 1 MiB; inspect output is a few KiB.
type socketClient struct {
	client  *http.Client
	base    string // scheme://host[/version-prefix]
	timeout time.Duration
	name    string // for error messages
}

func newSocketClient(name, socketPath, base string) (*socketClient, error) {
	if !strings.HasPrefix(socketPath, "/") {
		return nil, fmt.Errorf("%s: socket must be an absolute path", name)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &socketClient{
		client:  &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base:    base,
		timeout: 10 * time.Second,
		name:    name,
	}, nil
}

// StopGrace is the grace period sent with every stop (podman `timeout=`, docker `t=`):
// SIGTERM, then SIGKILL after this long. Both daemons answer the stop request only
// once the container has actually stopped, so a workload that ignores SIGTERM (a
// `sleep` as PID 1 does; many agent harnesses do too) makes the call take the whole
// grace period. The HTTP timeout for a stop is therefore StopGrace plus the normal
// call budget, and the controller gives its terminate call the same allowance;
// a 10 s HTTP timeout on a 10 s grace period timed out against the live daemon.
const StopGrace = 10 * time.Second

func (s *socketClient) do(ctx context.Context, method, path string, q url.Values) (int, []byte, error) {
	return s.doWithin(ctx, s.timeout, method, path, q)
}

func (s *socketClient) doWithin(ctx context.Context, timeout time.Duration, method, path string, q url.Values) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := s.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// checkID admits only a full 64-hex container id. Names and short ids are refused
// before any request goes out: a name can be re-bound to a different container, and
// a short id is a prefix match the runtime resolves, not an identity.
func checkID(id string) error {
	if len(id) != 64 {
		return fmt.Errorf("refusing non-full container id")
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("refusing non-full container id")
		}
	}
	return nil
}

// enrolledFilter is the `filters` query both engines accept on the list endpoint.
const enrolledFilter = `{"label":["river3.enroll=true"]}`
