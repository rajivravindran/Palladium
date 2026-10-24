package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"river3.local/containment/apiclient"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

// Policy is one validated profile set and the engine compiled from it. It is never
// modified once stored; a change builds a new one and SetPolicy swaps it in whole.
type Policy struct {
	Engine   *policy.Engine
	Profiles map[string]*policy.Profile // the set as written (files or API bundle); never the derived copies
	Revision string                     // API bundle revision; "" when the set came from local files
	// Egress is the domain-resolution table the Engine was compiled with (CONTRACTS.md
	// §5): profile → host prefixes appended to a copy of its EgressAllow. Nil when no
	// profile names a domain, or when domain egress is off. Profiles above is NOT
	// decorated; the console's revision and the incident facts describe the set as the
	// admin wrote it.
	Egress    map[string][]string
	egressKey string // fingerprint of Egress, so a refresh that changes nothing swaps nothing
}

// Policy returns the set currently being enforced.
func (c *Controller) Policy() *Policy { return c.pol.Load() }

// BuildPolicy checks raw profiles exactly as the file loader does, refuses a set that
// would leave an enrolled workload without its profile, and compiles an engine.
func BuildPolicy(docs []policy.Document, revision string, reg *registry.Registry) (*Policy, error) {
	loaded, err := policy.ParseProfiles(docs)
	if err != nil {
		return nil, err
	}
	for _, w := range reg.Workloads() {
		if _, ok := loaded[w.Profile]; !ok {
			return nil, fmt.Errorf("workload %s is assigned profile %q, which this set does not contain", w.AssetID, w.Profile)
		}
	}
	names := make([]string, 0, len(loaded))
	for n := range loaded {
		names = append(names, n)
	}
	sort.Strings(names)
	list := make([]policy.Profile, 0, len(names))
	for _, n := range names {
		list = append(list, *loaded[n])
	}
	engine, err := policy.NewEngine(list, policy.Options{})
	if err != nil {
		return nil, err
	}
	return &Policy{Engine: engine, Profiles: loaded, Revision: revision}, nil
}

// BundleDocs turns an API bundle into documents for BuildPolicy.
func BundleDocs(b apiclient.PolicyBundle) []policy.Document {
	docs := make([]policy.Document, 0, len(b.Profiles))
	for i, raw := range b.Profiles {
		docs = append(docs, policy.Document{Source: fmt.Sprintf("api profile #%d", i+1), Data: raw})
	}
	return docs
}

// SetPolicy swaps the enforced set. Decisions already in progress finish on the set
// they started with; an action they request is revalidated against the new set.
// With domain egress on, the engine actually stored is compiled from copies of the
// profiles carrying the addresses already resolved (Egress.Derive); ApplyPolicy
// resolves new names first.
func (c *Controller) SetPolicy(p *Policy) {
	if c.cfg.Egress != nil {
		p = c.cfg.Egress.Derive(p)
	}
	c.pol.Store(p)
}

// SyncPolicy fetches the API's profile set and swaps it in when its revision changed and
// every profile in it compiles. On any failure the current set stays in force: a bad edit
// or an unreachable API never leaves the node without policy.
func (c *Controller) SyncPolicy(ctx context.Context) error {
	if c.cfg.API == nil {
		return fmt.Errorf("policy sync needs the API")
	}
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	b, err := c.cfg.API.PolicyBundle(ctx)
	if err != nil {
		return fmt.Errorf("fetch policy bundle: %w", err)
	}
	cur := c.pol.Load()
	if b.Revision != cur.Revision && b.Revision != c.seenRev {
		c.seenRev = b.Revision
		p, err := BuildPolicy(BundleDocs(b), b.Revision, c.cfg.Registry.Get())
		if err != nil {
			c.syncErr = err.Error()
			c.cfg.Log.Error("policy.rejected", "revision", short(b.Revision), "err", err, "active", short(cur.Revision))
		} else {
			c.syncErr = ""
			c.ApplyPolicy(ctx, p)
			if err := c.saveCache(b); err != nil {
				c.cfg.Log.Warn("policy.cache", "err", err)
			}
			c.cfg.Log.Info("policy.applied", "revision", short(b.Revision), "profiles", len(p.Profiles))
		}
	} else if b.Revision == cur.Revision {
		c.seenRev, c.syncErr = b.Revision, ""
	}
	active := c.pol.Load()
	report := apiclient.PolicyReport{SeenRevision: c.seenRev, ActiveRevision: active.Revision,
		Profiles: len(active.Profiles), Error: c.syncErr}
	key := fmt.Sprintf("%s|%s|%d|%s", report.SeenRevision, report.ActiveRevision, report.Profiles, report.Error)
	if key != c.reported || time.Since(c.reportedAt) > time.Minute {
		if err := c.cfg.API.ReportPolicy(ctx, report); err != nil {
			return fmt.Errorf("report policy status: %w", err)
		}
		c.reported, c.reportedAt = key, time.Now()
	}
	return nil
}

// RunPolicySync calls SyncPolicy every interval until ctx ends.
func (c *Controller) RunPolicySync(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := c.SyncPolicy(ctx); err != nil && ctx.Err() == nil {
			c.cfg.Log.Warn("policy.sync", "err", err, "active", short(c.pol.Load().Revision))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// saveCache keeps the last applied bundle so a restart while the API is down still
// starts with the console's policy rather than nothing.
func (c *Controller) saveCache(b apiclient.PolicyBundle) error {
	return SavePolicyCache(c.cfg.PolicyCache, b)
}

// StartupPolicy picks the set a -profiles-from-api controller starts with: the API's
// current set, else the last one applied (the cache at cachePath), else nil so the
// caller falls back to its local files until the API has valid profiles. A set that
// fails the engine's checks is never used.
//
// When the API's set is used it is written to the cache here, not only on the first
// later change in SyncPolicy. Otherwise a controller that starts from the API and is
// restarted while the API is down (the common case: both come back after a host
// reboot, the API more slowly) finds no cache and silently falls back to the local
// example files, which are all shadow.
func StartupPolicy(ctx context.Context, log *slog.Logger, api *apiclient.Client, reg *registry.Registry, cachePath string) (*Policy, string) {
	if api == nil {
		return nil, ""
	}
	fetch, cancel := context.WithTimeout(ctx, 15*time.Second)
	b, err := api.PolicyBundle(fetch)
	cancel()
	switch {
	case err != nil:
		log.Warn("policy.fetch", "err", err)
	case len(b.Profiles) == 0:
		log.Warn("policy.fetch", "note", "the API has no policies yet; add them in the console")
	default:
		p, err := BuildPolicy(BundleDocs(b), b.Revision, reg)
		if err == nil {
			if err := SavePolicyCache(cachePath, b); err != nil {
				log.Warn("policy.cache", "err", err)
			}
			return p, "api"
		}
		log.Error("policy.rejected", "revision", short(b.Revision), "err", err)
	}
	if cachePath == "" {
		return nil, ""
	}
	cached, err := LoadPolicyCache(cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error("policy.cache", "err", err)
		}
		return nil, ""
	}
	p, err := BuildPolicy(BundleDocs(cached), cached.Revision, reg)
	if err != nil {
		log.Error("policy.cache", "err", err)
		return nil, ""
	}
	log.Warn("policy.cache", "note", "starting with the last policy set applied from the API", "path", cachePath, "revision", short(cached.Revision))
	return p, "cache"
}

// SavePolicyCache writes a bundle atomically (temp file, fsync, rename) to path.
// An empty path disables caching.
func SavePolicyCache(path string, b apiclient.PolicyBundle) error {
	if path == "" {
		return nil
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadPolicyCache reads a bundle written by saveCache.
func LoadPolicyCache(path string) (apiclient.PolicyBundle, error) {
	var b apiclient.PolicyBundle
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("policy cache %s: %w", path, err)
	}
	return b, nil
}
