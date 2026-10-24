package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// Docker talks to the Docker Engine API over its unix socket (CONTRACTS.md §4.2).
//
// Paths, all under the versioned prefix /v1.43 (Engine API 1.43 = Docker 24; the
// daemon this was verified against reports ApiVersion 1.56 / MinAPIVersion 1.40, so
// 1.43 is accepted and pins the response shapes relied on below):
//
//	GET  /containers/{id}/json          inspect; 404 = Missing; generation = State.StartedAt
//	POST /containers/{id}/pause         204 = ok, 304 = already in that state
//	POST /containers/{id}/unpause       204 / 304
//	POST /containers/{id}/stop?t=10     204 / 304; graceful, the container stays inspectable
//	GET  /containers/json?all=false&filters={"label":["river3.enroll=true"]}   discovery
//
// Status mapping from State.Status: running → Running, paused → Paused, exited and
// dead → Exited, everything else (created, restarting, removing) → Unknown. A
// restarting container is neither paused nor proven stopped, so the controller
// records UNKNOWN rather than claiming either. The exit of a paused container is
// FAILED for a pause, as for every adapter (controller.verify).
//
// Only the full 64-hex id is sent; see checkID. Terminate is `stop` (SIGTERM, then
// SIGKILL after 10 s), never `kill` or `rm`, so the evidence remains inspectable.
type Docker struct {
	c *socketClient
}

// NewDocker returns an adapter on the daemon socket (default /var/run/docker.sock).
func NewDocker(socketPath string) (*Docker, error) {
	c, err := newSocketClient("docker", socketPath, "http://docker/v1.43")
	if err != nil {
		return nil, err
	}
	return &Docker{c: c}, nil
}

func (d *Docker) Name() string             { return "docker" }
func (d *Docker) Actions() []policy.Action { return []policy.Action{policy.Pause} }

func (d *Docker) Inspect(ctx context.Context, id string) (Info, error) {
	if err := checkID(id); err != nil {
		return Info{}, fmt.Errorf("docker: %w", err)
	}
	code, body, err := d.c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil)
	if err != nil {
		return Info{}, fmt.Errorf("docker inspect: %w", err)
	}
	if code == http.StatusNotFound {
		return Info{ContainerID: id, Status: Missing}, nil
	}
	if code != http.StatusOK {
		return Info{}, fmt.Errorf("docker inspect: HTTP %d %s", code, strings.TrimSpace(string(body)))
	}
	var out struct {
		ID    string `json:"Id"`
		State struct {
			Status    string `json:"Status"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Info{}, fmt.Errorf("docker inspect: %w", err)
	}
	if out.ID == "" {
		return Info{}, fmt.Errorf("docker inspect: response has no Id")
	}
	info := Info{ContainerID: out.ID, Generation: out.State.StartedAt}
	switch out.State.Status {
	case "running":
		info.Status = Running
	case "paused":
		info.Status = Paused
	case "exited", "dead":
		info.Status = Exited
	default: // created, restarting, removing
		info.Status = Unknown
	}
	return info, nil
}

func (d *Docker) mutate(ctx context.Context, id, verb string, q url.Values) error {
	if err := checkID(id); err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	timeout := d.c.timeout
	if verb == "stop" {
		timeout += StopGrace // the daemon replies only after the container has stopped
	}
	code, body, err := d.c.doWithin(ctx, timeout, http.MethodPost, "/containers/"+id+"/"+verb, q)
	if err != nil {
		return fmt.Errorf("docker %s: %w", verb, err)
	}
	if code == http.StatusNoContent || code == http.StatusNotModified {
		return nil
	}
	// 409 "is already paused" / "is not paused" and 404 end up here. The controller
	// records the message as adapter_error and still decides from Inspect.
	return fmt.Errorf("docker %s: HTTP %d %s", verb, code, strings.TrimSpace(string(body)))
}

func (d *Docker) Pause(ctx context.Context, id string) error { return d.mutate(ctx, id, "pause", nil) }
func (d *Docker) Resume(ctx context.Context, id string) error {
	return d.mutate(ctx, id, "unpause", nil)
}
func (d *Docker) Terminate(ctx context.Context, id string) error {
	return d.mutate(ctx, id, "stop", url.Values{"t": {strconv.Itoa(int(StopGrace / time.Second))}})
}

// ListEnrolled: GET /containers/json?all=false&filters={"label":["river3.enroll=true"]}
// followed by one Inspect per container. The list entry has no StartedAt, and the
// registry needs the exact string Inspect will report, so the extra round trip is
// what guarantees an enrolled generation verifies. all=false excludes created and
// exited containers but keeps paused ones, which must stay enrolled so an operator
// can resume them.
func (d *Docker) ListEnrolled(ctx context.Context) ([]registry.Container, error) {
	q := url.Values{"all": {"false"}, "filters": {enrolledFilter}}
	code, body, err := d.c.do(ctx, http.MethodGet, "/containers/json", q)
	if err != nil {
		return nil, fmt.Errorf("docker list: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("docker list: HTTP %d %s", code, strings.TrimSpace(string(body)))
	}
	var rows []listRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("docker list: %w", err)
	}
	return listWithGenerations(ctx, rows, d.Inspect)
}
