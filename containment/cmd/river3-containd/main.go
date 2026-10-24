// river3-containd is the node-local containment controller.
//
// It evaluates authenticated sensor events with the policy engine, performs at
// most one verified automatic action per eligible candidate through a fixed
// adapter, executes authenticated operator resume/terminate requests, and
// reports every outcome to the River3 API.
//
// Secrets come from the environment only, never flags:
//
//	RIVER3_CONTAINMENT_TOKEN   machine token, role "containment"   (required with -api)
//	RIVER3_POLICY_TOKEN        machine token, role "policy"        (optional; posts incidents/workloads)
//	RIVER3_WEBHOOK_SECRET      shared with the API for signed action webhooks (optional)
//	RIVER3_GATEWAY_SECRET      shared with the customer gateway; signs session revokes (-session-adapter gateway, ≥32 chars)
//	RIVER3_GUARD_URL           model guard endpoint (-guard laya: laya-serve base, default http://127.0.0.1:8600;
//	                           -guard llm: OpenAI-compatible base, default http://127.0.0.1:11434/v1)
//	RIVER3_GUARD_TOKEN         -guard laya: optional bearer token (laya-serve's LAYA_API_KEY)
//	RIVER3_GUARD_MODEL         -guard llm: model name (default qwen3:8b)
//
// Without -api the controller runs offline: decisions and actions are journaled
// locally and nothing is reported. Without RIVER3_POLICY_TOKEN the containment
// token is used for incidents too, which only works with a custom combined role.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/apiclient"
	"river3.local/containment/controller"
	"river3.local/containment/guard"
	"river3.local/containment/journal"
	"river3.local/containment/registry"
	policy "river3.local/policy"
)

func main() {
	profilesDir := flag.String("profiles", "../policy/examples/profiles", "directory of profile JSON files")
	fromAPI := flag.Bool("profiles-from-api", false, "enforce the policies admins edit in the console (needs -api); -profiles is used only until the API has any")
	profileSync := flag.Duration("profile-sync", 10*time.Second, "with -profiles-from-api: how often to fetch policy changes")
	registryPath := flag.String("registry", "fixtures/registry.json", "trusted enrollment file")
	journalPath := flag.String("journal", "river3-containd.journal", "durable journal (append-only JSONL)")
	listen := flag.String("listen", "127.0.0.1:8787", "address for /v1/events, /river3/actions and /healthz")
	apiURL := flag.String("api", "", "River3 API base URL (https://..., or http://127.0.0.1:8000 for dev); empty = offline")
	adapterName := flag.String("adapter", "mock", "runtime adapter: mock | podman | docker | openshell")
	podmanSock := flag.String("podman-socket", "/run/podman/podman.sock", "libpod API socket (adapter=podman, -runtime podman)")
	dockerSock := flag.String("docker-socket", "/var/run/docker.sock", "Docker Engine API socket (adapter=docker, -runtime docker)")
	fromRuntime := flag.Bool("registry-from-runtime", false, "enrol workloads from labelled containers (river3.enroll=true) instead of the -registry file's workloads; sensors still come from the file")
	registryRefresh := flag.Duration("registry-refresh", 10*time.Second, "with -registry-from-runtime: how often to re-list the runtime")
	registryReload := flag.Duration("registry-reload", 5*time.Second, "how often to check the -registry file's mtime and reload it when changed (0 = off); SIGHUP reloads it at any time")
	runtimeName := flag.String("runtime", "", "with -registry-from-runtime: which runtime to list, podman | docker (default: the adapter's own)")
	openshellBin := flag.String("openshell-bin", "openshell", "adapter=openshell: the OpenShell CLI")
	openshellMap := flag.String("openshell-sandboxes", "fixtures/openshell-sandboxes.json", "adapter=openshell: JSON map of container id -> {sandbox, generation}")
	mockFixtures := flag.String("mock-containers", "", "adapter=mock: seed containers from the registry as running (set to 'registry')")
	reportUnknown := flag.Bool("report-unknown", false, "also post UNKNOWN decisions as incidents")
	pollEvery := flag.Duration("poll", 5*time.Second, "how often to poll /api/v1/actions")
	flushEvery := flag.Duration("flush", 10*time.Second, "how often to retry unreported results")
	heartbeat := flag.Duration("sensor-heartbeat", 0, "treat a workload as unhealthy if its sensor is silent this long (0 = off)")
	guardMode := flag.String("guard", "off", "model guard: off | laya | llm. laya = the Laya decision model via laya-serve's POST /v1/systemone; RIVER3_GUARD_URL (default "+guard.DefaultLayaURL+", https or loopback http), RIVER3_GUARD_TOKEN (optional bearer = the server's LAYA_API_KEY). llm = an OpenAI-compatible chat-completions endpoint; RIVER3_GUARD_URL (default "+guard.DefaultLLMURL+") and RIVER3_GUARD_MODEL (default "+guard.DefaultLLMModel+")")
	guardChannels := flag.String("guard-channels", "A,B", "which channels the guard assesses: A (structural facts), B (untrusted payload), or A,B")
	guardTimeout := flag.Duration("guard-timeout", 0, "per-call model timeout; 0 = the mode's default (laya 3s, llm 8s). A timeout yields an unverified UNAVAILABLE assessment (engine: UNTRUSTED_GUARD_ASSESSMENT), never CONTINUE")
	guardMinConfidence := flag.Float64("guard-min-confidence", guard.DefaultMinConfidence, "-guard laya: an answer whose confidence is below this (0 < c <= 1) is an unverified UNAVAILABLE assessment, so the event is UNKNOWN rather than IN_SCOPE. Laya has no abstain option; this is where 'unknown' comes from. The base checkpoint is over-confident until fine-tuned: keep this conservative")
	sessionsFromAPI := flag.Bool("sessions-from-api", false, "bind workloads to their newest active gateway session from GET /api/v1/sessions?state=active (needs -api); clears the engine's NO_BOUND_SESSION blocker")
	sessionSync := flag.Duration("session-sync", 5*time.Second, "with -sessions-from-api: how often to refresh the session map")
	sessionAdapter := flag.String("session-adapter", "", "session adapter for REVOKE_SESSION: gateway (needs -gateway-url and RIVER3_GATEWAY_SECRET); empty = none, revoke is blocked with ADAPTER_UNAVAILABLE")
	gatewayURL := flag.String("gateway-url", "", "session-adapter=gateway: the customer gateway base URL (https://..., or http://127.0.0.1:PORT on the node); POST {url}/v1/sessions/{id}/revoke, GET {url}/v1/sessions/{id}")
	egressRefresh := flag.Duration("egress-refresh", time.Minute, "how often egress_allowed_domains are re-resolved (A/AAAA) into the enforced engine; 0 = off (domains are then never in scope)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(context.Background(), log, options{
		profiles: *profilesDir, fromAPI: *fromAPI, profileSync: *profileSync, registry: *registryPath, journal: *journalPath, listen: *listen, api: *apiURL,
		adapter: *adapterName, podmanSock: *podmanSock, dockerSock: *dockerSock, openshellBin: *openshellBin, openshellMap: *openshellMap,
		fromRuntime: *fromRuntime, registryRefresh: *registryRefresh, registryReload: *registryReload, runtime: *runtimeName,
		mockSeed: *mockFixtures == "registry", reportUnknown: *reportUnknown,
		poll: *pollEvery, flush: *flushEvery, heartbeat: *heartbeat,
		guard: *guardMode, guardChannels: *guardChannels, guardTimeout: *guardTimeout, guardMinConfidence: *guardMinConfidence,
		sessionsFromAPI: *sessionsFromAPI, sessionSync: *sessionSync, sessionAdapter: *sessionAdapter, gatewayURL: *gatewayURL,
		egressRefresh: *egressRefresh,
	}); err != nil {
		log.Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}

type options struct {
	profiles, registry, journal, listen, api, adapter, podmanSock, dockerSock string
	openshellBin, openshellMap                                                string
	mockSeed, reportUnknown, fromAPI, fromRuntime                             bool
	poll, flush, heartbeat, profileSync, registryRefresh, registryReload      time.Duration
	runtime                                                                   string
	guard, guardChannels                                                      string
	guardTimeout                                                              time.Duration
	guardMinConfidence                                                        float64
	sessionsFromAPI                                                           bool
	sessionSync                                                               time.Duration
	sessionAdapter, gatewayURL                                                string
	egressRefresh                                                             time.Duration
}

// validate refuses flag values the daemon cannot run with. time.NewTicker panics on a
// non-positive duration, so `-poll 0` used to crash the daemon after start-up (after the
// journal was opened and reconciled) instead of failing the command line. Intervals
// documented with "0 = off" (-sensor-heartbeat, -egress-refresh, -registry-reload) accept
// zero and refuse negatives; -guard-timeout 0 means "the guard mode's default" (laya 3 s,
// llm 8 s) and refuses negatives. -guard must name a known mode and
// -guard-min-confidence must be a probability in (0, 1].
func validate(o options) error {
	positive := map[string]time.Duration{"-poll": o.poll, "-flush": o.flush, "-profile-sync": o.profileSync,
		"-registry-refresh": o.registryRefresh, "-session-sync": o.sessionSync}
	for _, name := range []string{"-poll", "-flush", "-profile-sync", "-registry-refresh", "-session-sync"} {
		if positive[name] <= 0 {
			return fmt.Errorf("%s must be greater than zero (got %s)", name, positive[name])
		}
	}
	nonNegative := map[string]time.Duration{"-sensor-heartbeat": o.heartbeat, "-egress-refresh": o.egressRefresh,
		"-registry-reload": o.registryReload, "-guard-timeout": o.guardTimeout}
	for _, name := range []string{"-sensor-heartbeat", "-egress-refresh", "-registry-reload", "-guard-timeout"} {
		if nonNegative[name] < 0 {
			return fmt.Errorf("%s must be zero (off / default) or greater (got %s)", name, nonNegative[name])
		}
	}
	switch o.guard {
	case "", "off", "laya", "llm":
	default:
		return fmt.Errorf("unknown -guard %q (off | laya | llm)", o.guard)
	}
	if o.guard == "laya" && !(o.guardMinConfidence > 0 && o.guardMinConfidence <= 1) {
		return fmt.Errorf("-guard-min-confidence must be in (0, 1] (got %v)", o.guardMinConfidence)
	}
	if ch := strings.ToUpper(strings.ReplaceAll(o.guardChannels, " ", "")); o.guard != "" && o.guard != "off" {
		for _, part := range strings.Split(ch, ",") {
			if part != "A" && part != "B" {
				return fmt.Errorf("-guard-channels must be A, B or A,B (got %q)", o.guardChannels)
			}
		}
	}
	return nil
}

// guardTimeout is the per-call model timeout for the chosen mode: the flag when set,
// else laya 3 s (one forward pass is ~0.2–0.5 s on CPU) or llm 8 s.
func guardTimeout(o options) time.Duration {
	if o.guardTimeout > 0 {
		return o.guardTimeout
	}
	if o.guard == "llm" {
		return guard.DefaultLLMTimeout
	}
	return guard.DefaultLayaTimeout
}

func run(ctx context.Context, log *slog.Logger, o options) error {
	if err := validate(o); err != nil {
		return err
	}
	regFile, err := registry.LoadFile(o.registry)
	if err != nil {
		return err
	}
	if o.fromRuntime {
		// The runtime is the source of truth for workloads; the file keeps node + sensors.
		// Dropping the file's workloads here (rather than merging) means a stale static
		// entry can never shadow or outlive the container it once described.
		if n := len(regFile.Workloads); n > 0 {
			log.Warn("registry.file_workloads_ignored", "count", n, "note", "-registry-from-runtime: workloads come from container labels")
		}
		regFile.Workloads = nil
	}
	reg, err := registry.New(regFile)
	if err != nil {
		return err
	}

	if o.fromAPI && o.api == "" {
		return errors.New("-profiles-from-api needs -api")
	}
	if o.sessionsFromAPI && o.api == "" {
		return errors.New("-sessions-from-api needs -api")
	}

	// Session adapter (CONTRACTS.md §2.1). Checked before anything else is opened so a
	// short secret is a fatal misconfiguration at start, not a surprise at revoke time.
	var sessions adapter.SessionAdapter
	switch o.sessionAdapter {
	case "":
	case "gateway":
		if o.gatewayURL == "" {
			return errors.New("-session-adapter gateway needs -gateway-url")
		}
		secret := []byte(os.Getenv("RIVER3_GATEWAY_SECRET"))
		if len(secret) < adapter.MinGatewaySecret {
			return fmt.Errorf("RIVER3_GATEWAY_SECRET must be at least %d characters when -session-adapter gateway is set", adapter.MinGatewaySecret)
		}
		gw, err := adapter.NewGateway(o.gatewayURL, secret)
		if err != nil {
			return err
		}
		sessions = gw
		log.Info("session_adapter.gateway", "url", o.gatewayURL, "note", "gateway replies are Channel B: they settle whether a revoke took, never whether a violation exists")
	default:
		return fmt.Errorf("unknown -session-adapter %q (gateway)", o.sessionAdapter)
	}
	var api *apiclient.Client
	if o.api != "" {
		api, err = apiclient.New(apiclient.Config{BaseURL: o.api,
			ContainmentToken: os.Getenv("RIVER3_CONTAINMENT_TOKEN"), PolicyToken: os.Getenv("RIVER3_POLICY_TOKEN")})
		if err != nil {
			return err
		}
	} else {
		log.Warn("offline", "note", "no -api: decisions and actions are journaled locally and never reported")
	}

	cache := ""
	if o.fromAPI {
		cache = o.journal + ".policy.json"
	}
	// With discovery on, reg has no workloads yet, so the "every enrolled workload has
	// its profile" check in BuildPolicy is vacuous here; discovery applies it per
	// container instead (a container bound to an unknown profile is skipped, logged).
	pol, source, err := initialPolicy(ctx, log, o, api, reg, cache)
	if err != nil {
		return err
	}
	active := 0
	for _, p := range pol.Profiles {
		if p.Mode == policy.Active {
			active++
		}
	}

	var ad adapter.Adapter
	switch o.adapter {
	case "mock":
		m := adapter.NewMock()
		if o.mockSeed {
			for _, w := range reg.Workloads() {
				m.Add(w.ContainerID, w.Generation, adapter.Running)
			}
		}
		ad = m
	case "podman":
		ad, err = adapter.NewPodman(o.podmanSock)
		if err != nil {
			return err
		}
		log.Warn("adapter.podman", "note", "the podman adapter has not been exercised against a real runtime; see HANDOVER.md")
	case "docker":
		ad, err = adapter.NewDocker(o.dockerSock)
		if err != nil {
			return err
		}
		log.Info("adapter.docker", "socket", o.dockerSock, "api", "/v1.43")
	case "openshell":
		ad, err = adapter.NewOpenShell(o.openshellBin, o.openshellMap)
		if err != nil {
			return err
		}
		log.Warn("adapter.openshell", "note", "pause = `openshell sandbox stop`; not yet exercised against a real OpenShell gateway", "sandboxes", o.openshellMap)
	default:
		return fmt.Errorf("unknown adapter %q", o.adapter)
	}

	jr, err := journal.Open(o.journal)
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	defer jr.Close()

	var g guard.Guard
	ch := strings.ToUpper(o.guardChannels)
	switch o.guard {
	case "off", "":
	case "laya":
		base := os.Getenv("RIVER3_GUARD_URL")
		if base == "" {
			base = guard.DefaultLayaURL
		}
		l, err := guard.NewLaya(guard.LayaConfig{BaseURL: base, Token: os.Getenv("RIVER3_GUARD_TOKEN"), Timeout: guardTimeout(o),
			MinConfidence: o.guardMinConfidence, ChannelA: strings.Contains(ch, "A"), ChannelB: strings.Contains(ch, "B")})
		if err != nil {
			return err
		}
		g = l
		log.Info("guard.laya", "url", base, "token", os.Getenv("RIVER3_GUARD_TOKEN") != "", "channels", ch, "timeout", guardTimeout(o).String(),
			"min_confidence", o.guardMinConfidence, "note", "advisory; Channel B alone never contains; below min_confidence = unverified UNAVAILABLE")
	case "llm":
		base := os.Getenv("RIVER3_GUARD_URL")
		if base == "" {
			base = guard.DefaultLLMURL
		}
		model := os.Getenv("RIVER3_GUARD_MODEL")
		if model == "" {
			model = guard.DefaultLLMModel
		}
		l, err := guard.NewLLM(guard.LLMConfig{BaseURL: base, Model: model, Timeout: guardTimeout(o),
			ChannelA: strings.Contains(ch, "A"), ChannelB: strings.Contains(ch, "B")})
		if err != nil {
			return err
		}
		g = l
		log.Info("guard.llm", "url", base, "model", model, "channels", ch, "timeout", guardTimeout(o).String(), "note", "advisory; Channel B alone never contains")
	default:
		return fmt.Errorf("unknown -guard %q (off | laya | llm)", o.guard)
	}

	var egress *controller.Egress
	if o.egressRefresh > 0 {
		egress = &controller.Egress{Timeout: controller.DefaultEgressTimeout, Log: log}
	}
	holder := registry.NewHolder(reg)
	c, err := controller.New(controller.Config{Engine: pol.Engine, Profiles: pol.Profiles, Registry: holder, Adapter: ad,
		Journal: jr, API: api, Guard: g, Sessions: sessions, Egress: egress, ReportUnknown: o.reportUnknown, Log: log,
		HeartbeatWithin: o.heartbeat, PolicyCache: cache})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// ApplyPolicy resolves egress_allowed_domains (CONTRACTS.md §5) before the set is
	// enforced, so a connection to an allowed name is in scope from the first event.
	c.ApplyPolicy(ctx, pol)
	if egress != nil {
		if st := c.EgressStatus(); st != nil && len(st["names"].([]string)) > 0 {
			log.Info("egress.domains", "status", st, "refresh", o.egressRefresh.String())
		}
	}
	if o.sessionsFromAPI {
		// First sync before Start so the first events already see the bound sessions.
		// A failure is not fatal: the ticker retries, and until then no session is
		// bound, which blocks REVOKE_SESSION with NO_BOUND_SESSION, never a wrong revoke.
		syncCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := c.SyncSessions(syncCtx); err != nil {
			log.Warn("sessions.sync", "err", err.Error(), "note", "starting with no sessions bound; retrying every "+o.sessionSync.String())
		}
		cancel()
	}

	var disc *controller.Discovery
	if o.fromRuntime {
		src, name, err := discoverySource(o, ad)
		if err != nil {
			return err
		}
		disc = &controller.Discovery{Source: src, Base: regFile, Every: o.registryRefresh}
		// First pass before Start so reconciliation and the first events see the
		// runtime's workloads. A failure here is not fatal: the ticker retries, and
		// until then nothing is enrolled, which is alert-only, never a wrong action.
		if err := c.DiscoverOnce(ctx, disc); err != nil {
			log.Warn("registry.discovery", "runtime", name, "err", err.Error(), "note", "starting with no workloads enrolled; retrying every "+o.registryRefresh.String())
		}
		log.Info("registry.from_runtime", "runtime", name, "refresh", o.registryRefresh.String(), "workloads", len(holder.Get().Workloads()))
	}
	if err := c.Start(ctx); err != nil {
		return err
	}
	// Registry hot reload (CONTRACTS.md §5): SIGHUP always; the mtime poll when
	// -registry-reload > 0. With discovery on, the file's node and sensors are what
	// reload; the workloads keep coming from the runtime.
	reload := &controller.RegistryReload{Path: o.registry, Every: o.registryReload, Discovery: disc}
	if err := c.WatchRegistry(reload); err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	sessionAdapterName := ""
	if sessions != nil {
		sessionAdapterName = sessions.Name()
	}
	log.Info("startup", "profiles", len(pol.Profiles), "active_profiles", active, "policy_source", source, "workloads", len(holder.Get().Workloads()),
		"adapter", ad.Name(), "session_adapter", sessionAdapterName, "sessions_from_api", o.sessionsFromAPI, "egress_refresh", o.egressRefresh.String(),
		"registry_reload", o.registryReload.String(), "api", o.api != "", "journal", jr.Stats())

	secret := []byte(os.Getenv("RIVER3_WEBHOOK_SECRET"))
	if len(secret) > 0 && len(secret) < 32 {
		return errors.New("RIVER3_WEBHOOK_SECRET must be at least 32 characters")
	}
	srv := &controller.Server{C: c, WebhookSecret: secret, Async: true}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()
	go c.RunLoops(ctx, o.poll, o.flush)
	if o.fromAPI {
		go c.RunPolicySync(ctx, o.profileSync)
	}
	if disc != nil {
		go c.RunDiscovery(ctx, disc)
	}
	go c.RunRegistryReload(ctx, hup)
	if o.sessionsFromAPI {
		go c.RunSessionSync(ctx, o.sessionSync)
	}
	if egress != nil {
		go c.RunEgressRefresh(ctx, o.egressRefresh)
	}
	log.Info("listening", "addr", ln.Addr().String(), "webhook", len(secret) > 0)
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// initialPolicy picks the set to start with. With -profiles-from-api: the API's current
// set (cached next to the journal the moment it is accepted), else the cache, else the
// -profiles directory until the API has valid profiles. A set that fails the engine's
// checks is never used. The API/cache selection lives in controller.StartupPolicy so it
// is covered by tests; this wrapper only adds the file fallback.
func initialPolicy(ctx context.Context, log *slog.Logger, o options, api *apiclient.Client, reg *registry.Registry,
	cache string) (*controller.Policy, string, error) {
	if o.fromAPI {
		if p, source := controller.StartupPolicy(ctx, log, api, reg, cache); p != nil {
			return p, source, nil
		}
	}
	loaded, err := policy.LoadProfiles(o.profiles)
	if err != nil {
		return nil, "", fmt.Errorf("profiles: %w", err)
	}
	docs := make([]policy.Document, 0, len(loaded))
	for _, p := range loaded {
		data, err := json.Marshal(p)
		if err != nil {
			return nil, "", err
		}
		docs = append(docs, policy.Document{Source: p.Name, Data: data})
	}
	p, err := controller.BuildPolicy(docs, "", reg)
	if err != nil {
		return nil, "", fmt.Errorf("profiles: %w", err)
	}
	return p, "files", nil
}

// discoverySource picks what -registry-from-runtime lists. By default it is the adapter
// itself, so the generation the registry records and the one Inspect verifies against
// come from the same socket. -runtime overrides it (e.g. adapter=mock while listing a
// real docker daemon for a dry run); identity will then only verify if the adapter
// reports the same generations, which is the operator's problem to arrange.
func discoverySource(o options, ad adapter.Adapter) (adapter.Lister, string, error) {
	name := o.runtime
	if name == "" {
		name = ad.Name()
	}
	if name == ad.Name() {
		if l, ok := ad.(adapter.Lister); ok {
			return l, name, nil
		}
		return nil, "", fmt.Errorf("-registry-from-runtime: adapter %q cannot list containers; set -runtime podman|docker", ad.Name())
	}
	switch name {
	case "docker":
		d, err := adapter.NewDocker(o.dockerSock)
		return d, name, err
	case "podman":
		p, err := adapter.NewPodman(o.podmanSock)
		return p, name, err
	}
	return nil, "", fmt.Errorf("unknown -runtime %q (podman | docker)", name)
}
