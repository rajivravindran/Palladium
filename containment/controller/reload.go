package controller

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"river3.local/containment/registry"
)

// RegistryReload re-reads the enrollment file while the controller runs
// (CONTRACTS.md §5): on SIGHUP, and when the file's mtime or size changes, checked
// every Every (0 = SIGHUP only). The file is validated as a whole by the same loader
// that start-up uses and swapped in with Holder.Set; an invalid file is rejected,
// logged, exposed on /healthz as registry_error and the previous snapshot stays in
// force. Every reader (normalizer, operator path, event authentication, outbox)
// goes through Holder.Get on each request, so a swap is visible to the next event
// and to the refresh before any action.
//
// With -registry-from-runtime (Discovery set) the file supplies node and sensors
// only: a reload installs the new file as the discovery base and runs one discovery
// pass, which rebuilds the snapshot from the runtime plus the new sensors.
type RegistryReload struct {
	Path      string
	Every     time.Duration
	Discovery *Discovery // nil = static file: workloads come from the file

	mu       sync.Mutex // one reload at a time; also guards the fields below
	modTime  time.Time  // stat of the file as last read (loaded or rejected)
	size     int64
	loadedAt time.Time // last successful swap
	reloads  int       // successful reloads since start
	lastErr  string    // why the last attempt was rejected; "" when the file is in force
}

// WatchRegistry attaches a reload source. The file's current stat is recorded so the
// poll reacts to changes after this call, not to the file the controller started from.
func (c *Controller) WatchRegistry(r *RegistryReload) error {
	if r == nil || r.Path == "" {
		return fmt.Errorf("registry reload: a path is required")
	}
	st, err := os.Stat(r.Path)
	if err != nil {
		return fmt.Errorf("registry reload: %w", err)
	}
	r.mu.Lock()
	r.modTime, r.size, r.loadedAt = st.ModTime(), st.Size(), c.cfg.Clock()
	r.mu.Unlock()
	c.reload.Store(r)
	return nil
}

// ReloadRegistry re-reads the file unconditionally (SIGHUP, or a test). The error
// says why the file was rejected; the enforced registry is unchanged in that case.
func (c *Controller) ReloadRegistry(ctx context.Context) error {
	r := c.reload.Load()
	if r == nil {
		return fmt.Errorf("registry reload: not configured")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return c.reloadLocked(ctx, r)
}

// PollRegistry reloads only if the file's mtime or size differ from the last read.
// It returns whether a reload was attempted and, if so, its result.
func (c *Controller) PollRegistry(ctx context.Context) (bool, error) {
	r := c.reload.Load()
	if r == nil {
		return false, fmt.Errorf("registry reload: not configured")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := os.Stat(r.Path)
	if err != nil {
		// Transient during an atomic replace (rename) or a real deletion: either way the
		// enforced snapshot stays, and the next poll sees the new file's stat.
		if r.lastErr == "" {
			c.cfg.Log.Warn("registry.reload", "path", r.Path, "err", err.Error(), "kept", "current registry")
		}
		r.lastErr = "stat: " + err.Error()
		return false, err
	}
	if st.ModTime().Equal(r.modTime) && st.Size() == r.size {
		return false, nil
	}
	return true, c.reloadLocked(ctx, r)
}

// reloadLocked is the reload itself; r.mu is held.
func (c *Controller) reloadLocked(ctx context.Context, r *RegistryReload) error {
	// Record the stat before parsing so a file that fails validation is not re-parsed
	// and re-logged on every tick; only a further change triggers another attempt.
	if st, err := os.Stat(r.Path); err == nil {
		r.modTime, r.size = st.ModTime(), st.Size()
	}
	file, err := registry.LoadFile(r.Path)
	if err != nil {
		return c.rejectRegistry(r, err)
	}
	if r.Discovery != nil {
		// Workloads come from the runtime; the file may still carry stale static entries.
		file.Workloads = nil
		// Validate node + sensors with the same rules before touching the discovery base.
		if _, err := registry.New(file); err != nil {
			return c.rejectRegistry(r, err)
		}
		prev := c.cfg.Registry.Get()
		r.Discovery.rebase(file)
		if err := c.DiscoverOnce(ctx, r.Discovery); err != nil {
			// The file was valid and is installed as the base, but the snapshot in force
			// still carries the old sensors until the discovery loop's next successful
			// pass. Say so on /healthz until a later reload succeeds.
			r.lastErr = "file accepted; the discovery pass that applies it failed (retrying every refresh): " + err.Error()
			c.cfg.Log.Warn("registry.reloaded", "path", r.Path, "mode", "runtime", "note", r.lastErr)
			return err
		}
		r.lastErr, r.loadedAt = "", c.cfg.Clock()
		r.reloads++
		ch := registry.Compare(prev, c.cfg.Registry.Get())
		c.cfg.Log.Info("registry.reloaded", "path", r.Path, "mode", "runtime", "sensors_added", ch.SensorsAdded, "sensors_removed", ch.SensorsRemoved,
			"added", ch.Added, "removed", ch.Removed, "changed", ch.Changed)
		return nil
	}
	next, err := registry.New(file)
	if err != nil {
		return c.rejectRegistry(r, err)
	}
	// Same rule BuildPolicy applies from the other side: a workload bound to a profile
	// the enforced set lacks would error on every event and make every later policy
	// update un-applicable. The file is refused whole rather than enrolling the rest.
	profiles := c.pol.Load().Profiles
	for _, w := range next.Workloads() {
		if _, ok := profiles[w.Profile]; !ok {
			return c.rejectRegistry(r, fmt.Errorf("registry: workload %s is bound to profile %q, which the enforced policy set does not contain", w.AssetID, w.Profile))
		}
	}
	prev := c.cfg.Registry.Get()
	ch := registry.Compare(prev, next)
	c.cfg.Registry.Set(next)
	r.lastErr, r.loadedAt = "", c.cfg.Clock()
	r.reloads++
	// The API's workload record is re-sent for anything that changed or came back:
	// ensureWorkload remembers what it registered this process.
	c.enrolledMu.Lock()
	for _, lists := range [][]string{ch.Changed, ch.Removed} {
		for _, id := range lists {
			delete(c.enrolled, id)
		}
	}
	c.enrolledMu.Unlock()
	c.cfg.Log.Info("registry.reloaded", "path", r.Path, "mode", "file", "workloads", len(next.Workloads()),
		"added", ch.Added, "removed", ch.Removed, "changed", ch.Changed, "sensors_added", ch.SensorsAdded, "sensors_removed", ch.SensorsRemoved)
	return nil
}

func (c *Controller) rejectRegistry(r *RegistryReload, err error) error {
	r.lastErr = err.Error()
	c.cfg.Log.Error("registry.rejected", "path", r.Path, "err", err.Error(), "kept", "current registry",
		"workloads", len(c.cfg.Registry.Get().Workloads()))
	return err
}

// RunRegistryReload polls every r.Every (0 = never) and reloads on each signal from
// hup until ctx ends. Errors are logged by the reload itself.
func (c *Controller) RunRegistryReload(ctx context.Context, hup <-chan os.Signal) {
	r := c.reload.Load()
	if r == nil {
		return
	}
	var tick <-chan time.Time // nil when polling is off: blocks forever in select
	if r.Every > 0 {
		t := time.NewTicker(r.Every)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			_, _ = c.PollRegistry(ctx)
		case <-hup:
			c.cfg.Log.Info("registry.reload", "trigger", "SIGHUP", "path", r.Path)
			_ = c.ReloadRegistry(ctx)
		}
	}
}

// RegistryStatus is what /healthz reports about enrollment: the snapshot in force and,
// when reload is configured, the file, when it was last applied and why the last
// attempt was rejected ("" = the file on disk is the one in force).
func (c *Controller) RegistryStatus() (map[string]any, string) {
	reg := c.cfg.Registry.Get()
	out := map[string]any{"workloads": len(reg.Workloads()), "sensors": len(reg.Sensors())}
	r := c.reload.Load()
	if r == nil {
		return out, ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out["path"] = r.Path
	out["reloads"] = r.reloads
	out["loaded_at"] = r.loadedAt.UTC().Format(time.RFC3339)
	if r.Every > 0 {
		out["poll"] = r.Every.String()
	}
	out["from_runtime"] = r.Discovery != nil
	return out, r.lastErr
}
