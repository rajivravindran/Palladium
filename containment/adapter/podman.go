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

// Podman talks to the libpod REST API over a unix socket (`podman system service`).
// It is opt-in and has NOT been exercised against a real runtime yet — see
// HANDOVER.md. Only the full 64-hex container id is ever sent; names are refused
// because a name can be re-bound to a different container.
type Podman struct {
	c *socketClient
}

func NewPodman(socketPath string) (*Podman, error) {
	c, err := newSocketClient("podman", socketPath, "http://podman/v4.0.0/libpod")
	if err != nil {
		return nil, err
	}
	return &Podman{c: c}, nil
}

func (p *Podman) Name() string             { return "podman" }
func (p *Podman) Actions() []policy.Action { return []policy.Action{policy.Pause} }

func (p *Podman) Inspect(ctx context.Context, id string) (Info, error) {
	if err := checkID(id); err != nil {
		return Info{}, fmt.Errorf("podman: %w", err)
	}
	code, body, err := p.c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil)
	if err != nil {
		return Info{}, fmt.Errorf("podman inspect: %w", err)
	}
	if code == http.StatusNotFound {
		return Info{ContainerID: id, Status: Missing}, nil
	}
	if code != http.StatusOK {
		return Info{}, fmt.Errorf("podman inspect: HTTP %d", code)
	}
	var out struct {
		ID    string `json:"Id"`
		State struct {
			Status    string `json:"Status"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Info{}, fmt.Errorf("podman inspect: %w", err)
	}
	info := Info{ContainerID: out.ID, Generation: out.State.StartedAt}
	switch out.State.Status {
	case "running":
		info.Status = Running
	case "paused":
		info.Status = Paused
	case "exited", "stopped", "removing", "dead":
		info.Status = Exited
	default:
		info.Status = Unknown
	}
	return info, nil
}

func (p *Podman) mutate(ctx context.Context, id, verb string, q url.Values) error {
	if err := checkID(id); err != nil {
		return fmt.Errorf("podman: %w", err)
	}
	timeout := p.c.timeout
	if verb == "stop" {
		timeout += StopGrace // the daemon replies only after the container has stopped
	}
	code, body, err := p.c.doWithin(ctx, timeout, http.MethodPost, "/containers/"+id+"/"+verb, q)
	if err != nil {
		return fmt.Errorf("podman %s: %w", verb, err)
	}
	if code == http.StatusNoContent || code == http.StatusNotModified {
		return nil
	}
	return fmt.Errorf("podman %s: HTTP %d %s", verb, code, strings.TrimSpace(string(body)))
}

func (p *Podman) Pause(ctx context.Context, id string) error { return p.mutate(ctx, id, "pause", nil) }
func (p *Podman) Resume(ctx context.Context, id string) error {
	return p.mutate(ctx, id, "unpause", nil)
}
func (p *Podman) Terminate(ctx context.Context, id string) error {
	return p.mutate(ctx, id, "stop", url.Values{"timeout": {strconv.Itoa(int(StopGrace / time.Second))}})
}

// ListEnrolled: GET /v4.0.0/libpod/containers/json?all=false&filters={"label":["river3.enroll=true"]}
// then one Inspect per container, so the generation handed to the registry is the
// exact State.StartedAt string Inspect will compare against later (the list entry
// carries StartedAt as a unix integer, which would never match).
func (p *Podman) ListEnrolled(ctx context.Context) ([]registry.Container, error) {
	q := url.Values{"all": {"false"}, "filters": {enrolledFilter}}
	code, body, err := p.c.do(ctx, http.MethodGet, "/containers/json", q)
	if err != nil {
		return nil, fmt.Errorf("podman list: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("podman list: HTTP %d %s", code, strings.TrimSpace(string(body)))
	}
	var rows []listRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("podman list: %w", err)
	}
	return listWithGenerations(ctx, rows, p.Inspect)
}

// listRow is the subset of a list entry both engines return with these names.
type listRow struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

// listWithGenerations completes list rows with the generation from Inspect. A
// container that vanished between list and inspect is simply left out (it is not
// running any more); any other inspect failure fails the whole listing, because an
// incomplete set would un-enrol healthy workloads for the next refresh interval.
func listWithGenerations(ctx context.Context, rows []listRow, inspect func(context.Context, string) (Info, error)) ([]registry.Container, error) {
	out := make([]registry.Container, 0, len(rows))
	for _, r := range rows {
		if checkID(r.ID) != nil {
			return nil, fmt.Errorf("list returned a non-full container id %q", r.ID)
		}
		info, err := inspect(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		if info.Status == Missing {
			continue
		}
		labels := r.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		name := ""
		if len(r.Names) > 0 {
			name = r.Names[0]
		}
		out = append(out, registry.Container{ID: info.ContainerID, Name: name, Labels: labels, Generation: info.Generation})
	}
	return out, nil
}
