package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/registry"
)

// Discovery keeps the registry in step with the runtime (`-registry-from-runtime`,
// CONTRACTS.md §4.2). Each pass lists the labelled containers, builds a registry
// snapshot from them plus the file's node and sensors, and swaps it in whole with
// Holder.Set. A decision in progress keeps the snapshot it read; the next event, and
// the refresh before any action (act → Normalize → Revalidate), see the new one, so a
// restart between evaluation and action is caught exactly as before: the enrolled
// generation changed, the candidate aborts.
type Discovery struct {
	Source adapter.Lister
	Base   registry.File // node + sensors from -registry; its workloads are ignored
	Every  time.Duration // default 10 s

	// mu serialises passes and guards Base/last: a registry file reload (reload.go)
	// replaces Base and clears last from another goroutine while RunDiscovery ticks.
	mu   sync.Mutex
	last string // fingerprint of the last snapshot applied, to log on change only
}

// rebase installs a freshly loaded registry file as the node/sensor source and
// forgets the last fingerprint, so the next pass swaps even if the container set is
// unchanged (the sensors may be what changed).
func (d *Discovery) rebase(f registry.File) {
	d.mu.Lock()
	d.Base, d.last = f, ""
	d.mu.Unlock()
}

// DiscoverOnce runs one pass. It returns an error when the runtime could not be
// listed or the snapshot could not be built; the current registry stays in force
// either way, because an empty or partial list from a hiccup must not un-enrol
// every workload for an interval.
func (c *Controller) DiscoverOnce(ctx context.Context, d *Discovery) error {
	if d == nil || d.Source == nil {
		return fmt.Errorf("discovery: no runtime source")
	}
	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	containers, err := d.Source.ListEnrolled(listCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	profiles := c.pol.Load().Profiles
	known := func(name string) bool { _, ok := profiles[name]; return ok }
	next, skipped, err := registry.Discover(d.Base, containers, known)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	fp := registry.Fingerprint(next)
	for _, s := range skipped {
		fp += "!" + s.ContainerID + ":" + s.Reason
	}
	if fp == d.last {
		return nil // nothing changed: no swap, no log line
	}
	prev := c.cfg.Registry.Get()
	c.cfg.Registry.Set(next)
	d.last = fp
	diff := registry.DiffRegistries(prev, next)
	c.cfg.Log.Info("registry.discovered", "workloads", len(next.Workloads()), "added", diff.Added, "removed", diff.Removed,
		"restarted", diff.Restarted, "skipped", len(skipped))
	for _, s := range skipped {
		c.cfg.Log.Warn("registry.skipped", "container", short(s.ContainerID), "reason", s.Reason)
	}
	return nil
}

// RunDiscovery repeats DiscoverOnce every d.Every until ctx ends. Errors are logged
// and the last good snapshot stays in force.
func (c *Controller) RunDiscovery(ctx context.Context, d *Discovery) {
	every := d.Every
	if every <= 0 {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.DiscoverOnce(ctx, d); err != nil && ctx.Err() == nil {
				c.cfg.Log.Warn("registry.discovery", "err", err.Error())
			}
		}
	}
}
