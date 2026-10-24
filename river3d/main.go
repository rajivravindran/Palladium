// river3d is the River3 sensor daemon.
//
// Sources
//
//	-source ebpf   (linux/amd64, root) syscall tracepoints: observe openat / execve /
//	               connect of enrolled containers, outcome from the syscall return
//	-source lsm    (linux/amd64, root, kernel with the bpf LSM) BPF-LSM hooks
//	               file_open / bprm_check_security / socket_connect: same events,
//	               recorded BEFORE the operation (inline), and with -block-decoys the
//	               profile's decoy and protected files are denied with EPERM. Falls
//	               back to -source ebpf when the kernel has no bpf LSM.
//	-source falco  map Falco JSON alerts produced with falco/river3_rules.yaml (the Mac
//	               path: Falco runs inside the podman machine VM)
//
// Enrollment
//
//	-enroll FILE            explicit enrollments (wins every conflict)
//	-enroll-from-labels     discover labelled containers (river3.enroll=true, §4.1)
//	                        through -runtime docker|podman every -refresh
//	-discover docker|podman discover containers labelled river3.workload / river3.profile /
//	                        river3.kind through the Docker-compatible API on -runtime-socket,
//	                        every -refresh and on the runtime's event stream (contract §5)
//
// Hostnames (contract §4)
//
//	-resolve-hosts   resolve the hostnames named by the profiles (-shadow-profiles) and by
//	                 -hosts-file every -resolve-every, keep an IP → host cache for -host-ttl,
//	                 and set facts.target.host on connect events whose IP is in it
//
// Sinks (any combination)
//
//	-controller URL  POST each event to river3-containd /v1/events — the engine with
//	                 trusted context; RIVER3_SENSOR_TOKEN authenticates
//	-api URL         batch POST /api/v1/events to the hub for the console's history,
//	                 and POST /api/v1/workloads for every enrollment; RIVER3_INGEST_TOKEN
//	-stdout          JSONL on stdout (replayable into the controller or fixtures)
//	-shadow-profiles DIR  evaluate in-process, shadow-only, log decisions to stderr;
//	                 also the profile source for -block-decoys
//
// Secrets come from the environment only, never from flags.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	policy "river3.local/policy"
)

var logf = log.New(os.Stderr, "river3d ", log.LstdFlags|log.LUTC).Printf

func main() {
	source := flag.String("source", "ebpf", "ebpf | lsm | falco")
	enroll := flag.String("enroll", "enroll.json", "enrollment file: which containers to watch (\"\" for none with -enroll-from-labels)")
	fromLabels := flag.Bool("enroll-from-labels", false, "also enrol running containers labelled river3.enroll=true (see -runtime)")
	runtimeKind := flag.String("runtime", "podman", "container runtime for id → PID resolution and label discovery: podman | docker")
	podmanSock := flag.String("podman-socket", "/run/podman/podman.sock", "libpod socket (-runtime podman)")
	dockerSock := flag.String("docker-socket", "/var/run/docker.sock", "Engine API socket (-runtime docker)")
	discover := flag.String("discover", "", "enrol running containers labelled river3.workload/river3.profile/river3.kind through this runtime's Docker-compatible API: docker | podman (off when empty)")
	runtimeSock := flag.String("runtime-socket", "", "socket for -discover (default: -docker-socket or -podman-socket by runtime)")
	refresh := flag.Duration("refresh", 5*time.Second, "how often enrollment is re-resolved (container restarts, new labels, new decoy files)")
	resolveHosts := flag.Bool("resolve-hosts", false, "resolve the hostnames in the profiles' egress rules (and -hosts-file) and set facts.target.host on connect events")
	resolveEvery := flag.Duration("resolve-every", time.Minute, "how often -resolve-hosts re-resolves every name")
	hostTTL := flag.Duration("host-ttl", 10*time.Minute, "how long -resolve-hosts keeps an address → host entry after the round that last confirmed it")
	hostsFile := flag.String("hosts-file", "", "extra hostnames for -resolve-hosts, one per line (for sensors without -shadow-profiles)")
	sensorName := flag.String("name", "ebpf", "sensor name written into every event")
	controller := flag.String("controller", "", "river3-containd base URL (e.g. http://127.0.0.1:8787)")
	apiURL := flag.String("api", "", "River3 API base URL (e.g. http://127.0.0.1:8000)")
	stdout := flag.Bool("stdout", false, "also write events as JSON lines to stdout")
	shadow := flag.String("shadow-profiles", "", "evaluate in-process (shadow only) with profiles from this directory")
	blockDecoys := flag.Bool("block-decoys", false, "source=lsm: deny opens of each workload's profile decoys and protected_read files (needs -shadow-profiles)")
	falcoInput := flag.String("falco-input", "-", "source=falco: JSON-lines file, or - for stdin")
	falcoListen := flag.String("falco-listen", "", "source=falco: also accept Falco http_output POSTs on this address (e.g. 127.0.0.1:8788)")
	flag.Parse()

	if err := run(context.Background(), options{
		source: *source, enroll: *enroll, fromLabels: *fromLabels, runtime: *runtimeKind,
		podmanSock: *podmanSock, dockerSock: *dockerSock, refresh: *refresh, name: *sensorName,
		controller: *controller, api: *apiURL, stdout: *stdout, shadow: *shadow, blockDecoys: *blockDecoys,
		falcoInput: *falcoInput, falcoListen: *falcoListen,
		discover: *discover, runtimeSock: *runtimeSock,
		resolveHosts: *resolveHosts, resolveEvery: *resolveEvery, hostTTL: *hostTTL, hostsFile: *hostsFile,
	}); err != nil {
		logf("fatal: %v", err)
		os.Exit(1)
	}
}

type options struct {
	source, enroll, runtime, podmanSock, dockerSock, name, controller, api, shadow, falcoInput, falcoListen string
	discover, runtimeSock, hostsFile                                                                        string
	refresh, resolveEvery, hostTTL                                                                          time.Duration
	stdout, fromLabels, blockDecoys, resolveHosts                                                           bool
}

func (o options) socket() string {
	if o.runtime == "docker" {
		return o.dockerSock
	}
	return o.podmanSock
}

// discoverSocket is the socket for -discover: -runtime-socket when given, else the
// per-runtime default flag.
func (o options) discoverSocket() string {
	if o.runtimeSock != "" {
		return o.runtimeSock
	}
	if o.discover == "docker" {
		return o.dockerSock
	}
	return o.podmanSock
}

func run(ctx context.Context, o options) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch o.source {
	case "ebpf", "lsm", "falco":
	default:
		return fmt.Errorf("unknown source %q", o.source)
	}
	if o.blockDecoys && o.source != "lsm" {
		return errors.New("-block-decoys needs -source lsm")
	}
	if o.blockDecoys && o.shadow == "" {
		return errors.New("-block-decoys needs the profiles: give -shadow-profiles DIR")
	}

	switch o.discover {
	case "", "docker", "podman":
	default:
		return fmt.Errorf("-discover must be docker or podman, not %q", o.discover)
	}
	discovering := o.fromLabels || o.discover != ""

	// --- enrollment inputs -------------------------------------------------------
	var enrollments []Enrollment
	if o.enroll != "" {
		list, err := loadEnrollments(o.enroll)
		switch {
		case err == nil:
			enrollments = list
		case discovering && errors.Is(err, os.ErrNotExist):
			logf("enroll: %s not found; enrolling from discovery only", o.enroll)
		default:
			return err
		}
	} else if !discovering {
		return errors.New("no enrollment: give -enroll FILE, -enroll-from-labels or -discover")
	}
	needRuntime := o.fromLabels
	if o.source != "falco" {
		for _, en := range enrollments {
			needRuntime = needRuntime || en.ContainerID != ""
		}
	}
	// One runtime client. With -discover it is the Docker-compatible client on that
	// runtime's socket, and it serves everything: discovery, -enroll-from-labels and
	// the id → PID resolution of file and discovered containers alike (they all run
	// on this host's one runtime). Without -discover, -runtime picks the client as before.
	var rt ContainerRuntime
	var disc *discoverer
	switch {
	case o.discover != "":
		c, err := newCompatClient(o.discover, o.discoverSocket())
		if err != nil {
			return err
		}
		disc = newDiscoverer(c, o.discover)
		rt = c
		if needRuntime && o.runtime != o.discover {
			logf("discover: using the %s socket for every container; -runtime %s is ignored", o.discover, o.runtime)
		}
	case needRuntime:
		c, err := newRuntimeClient(o.runtime, o.socket())
		if err != nil {
			return err
		}
		rt = c
	}

	// --- sinks ------------------------------------------------------------------
	var sinks []Sink
	var apiCli *apiClient
	if o.controller != "" {
		s, err := newControllerSink(o.controller, os.Getenv("RIVER3_SENSOR_TOKEN"), 0)
		if err != nil {
			return fmt.Errorf("%w (set RIVER3_SENSOR_TOKEN)", err)
		}
		sinks = append(sinks, s)
	}
	if o.api != "" {
		s, err := newAPISink(o.api, os.Getenv("RIVER3_INGEST_TOKEN"), 0, 0, 0)
		if err != nil {
			return fmt.Errorf("%w (set RIVER3_INGEST_TOKEN)", err)
		}
		sinks = append(sinks, s)
		apiCli = s.api
	}
	if o.stdout {
		sinks = append(sinks, newStdoutSink(os.Stdout))
	}
	if len(sinks) == 0 && o.shadow == "" {
		return errors.New("no sink: give -controller, -api, -stdout or -shadow-profiles")
	}
	emit := fanout{sinks}.Emit
	var profiles map[string]*policy.Profile
	if o.shadow != "" {
		sh, err := newShadowEval(o.shadow, os.Stderr)
		if err != nil {
			return fmt.Errorf("shadow: %w", err)
		}
		profiles = sh.profiles
		base := emit
		emit = func(ev Event) {
			base(ev)
			sh.Emit(ev)
		}
		logf("shadow evaluation on (profiles=%s); decisions are advisory, never actions", o.shadow)
	}
	var hosts hostLookup
	if o.resolveHosts {
		names := hostnamesFromProfiles(profiles)
		if o.hostsFile != "" {
			extra, err := loadHostsFile(o.hostsFile)
			if err != nil {
				return fmt.Errorf("hosts-file: %w", err)
			}
			names = append(names, extra...)
		}
		hr := newHostResolver(nil, o.hostTTL, logf)
		hr.SetNames(names)
		if len(hr.Names()) == 0 {
			logf("warning: -resolve-hosts is on but no hostname was found in the profiles or -hosts-file; target.host will never be set")
		}
		// The first round runs in the background: 256 names at 2 s each over 8 lanes
		// could otherwise hold the sensor back for a minute.
		go hr.Run(ctx, o.resolveEvery)
		hosts = hr
		logf("resolve-hosts on: %d name(s) every %s, ttl %s", len(hr.Names()), o.resolveEvery, o.hostTTL)
	}
	for _, s := range sinks {
		go s.Run(ctx)
	}

	// --- enrollment ---------------------------------------------------------------
	watch := newWatchlist()
	enroller := &Enroller{Enrollments: enrollments, Watch: watch, Log: logf}
	var sources []func(context.Context) ([]Enrollment, []string, error)
	if o.fromLabels {
		labelRT := rt
		sources = append(sources, func(ctx context.Context) ([]Enrollment, []string, error) { return discoverEnrollments(ctx, labelRT) })
	}
	if disc != nil {
		sources = append(sources, disc.Discover)
		if c, ok := disc.rt.(*runtimeClient); ok {
			// The runtime's event stream asks for an immediate refresh on any container
			// lifecycle event; the periodic refresh is the fallback when it is unavailable.
			go c.Events(ctx, enroller.Kick, logf)
		}
	}
	if len(sources) > 0 {
		enroller.Discover = combineDiscovery(sources...)
	}
	if o.source != "falco" {
		enroller.Runtime = rt // may be nil when every enrollment is a pid/mntns shortcut
	}
	if apiCli != nil {
		// Registration happens as workloads appear (labels can show up any time);
		// off the enroller's path so a slow API never delays watching.
		enroller.OnEnrolled = func(en Enrollment) { go registerWorkload(ctx, apiCli, en) }
	}

	switch o.source {
	case "ebpf", "lsm":
		if !ebpfSupported {
			return errors.New("the eBPF sensor only runs on linux/amd64; use -source falco")
		}
		mode := modeTracepoint
		if o.source == "lsm" {
			mode = modeLSM
		}
		src, err := openEBPF(mode)
		if err != nil && mode == modeLSM && errors.Is(err, errNoBPFLSM) {
			if o.blockDecoys {
				// Silently not enforcing would be worse than not starting.
				return fmt.Errorf("-block-decoys requested but inline blocking is impossible here: %w", err)
			}
			logf("warning: %v; falling back to the tracepoint source (no inline events)", err)
			mode = modeTracepoint
			src, err = openEBPF(mode)
		}
		if err != nil {
			return err
		}
		defer src.Close()
		enroller.SetWatched = src.setWatched
		// Content-based executable identity: hash the executed file and look it up in
		// a per-workload table of the image's own binaries.
		images := newImageIndex("", logf)
		enroller.Images = images
		dec := &Decoder{Sensor: o.name, Watch: watch, Clock: bootClock(), Images: images, Hosts: hosts}
		if o.blockDecoys {
			blocker := newInodeBlocker(profiles, src.setBlocked, logf)
			enroller.Inodes = blocker
			dec.Inodes = blocker
		}
		if err := enroller.Refresh(ctx); err != nil {
			return err
		}
		if len(watch.Snapshot()) == 0 {
			logf("warning: no enrollment resolved to a mount namespace yet; nothing is watched until one does")
		}
		go enroller.Run(ctx, o.refresh)
		logf("%s sensor attached; watching %d namespace(s); block-decoys=%v; sinks=%s", src.Mode(), len(watch.Snapshot()), o.blockDecoys, sinkNames(sinks))
		go reportStats(ctx, sinks)
		return src.Run(ctx, dec, emit)

	case "falco":
		if err := enroller.Refresh(ctx); err != nil {
			return err
		}
		go enroller.Run(ctx, o.refresh)
		fa := &FalcoAdapter{Sensor: o.name, Watch: watch, Hosts: hosts}
		go reportStats(ctx, sinks)
		if o.falcoListen != "" {
			ln, err := net.Listen("tcp", o.falcoListen)
			if err != nil {
				return err
			}
			mux := http.NewServeMux()
			mux.Handle("/falco", fa.Handler(emit))
			srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func() { <-ctx.Done(); _ = srv.Close() }()
			go func() {
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logf("falco listener: %v", err)
				}
			}()
			logf("falco adapter listening on %s/falco", ln.Addr())
		}
		if o.falcoInput == "" {
			<-ctx.Done()
			return nil
		}
		in := os.Stdin
		if o.falcoInput != "-" {
			f, err := os.Open(o.falcoInput)
			if err != nil {
				return err
			}
			defer f.Close()
			in = f
		}
		logf("falco adapter reading %s; sinks=%s", o.falcoInput, sinkNames(sinks))
		if err := fa.ReadStream(ctx, in, emit); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		// Let the sinks drain before exit when reading a finite file.
		drain(sinks)
		logf("falco: mapped=%d unenrolled=%d ignored=%d", fa.Mapped, fa.Unenrolled, fa.Ignored)
		return nil
	}
	return fmt.Errorf("unknown source %q", o.source)
}

func sinkNames(sinks []Sink) string {
	s := ""
	for i, k := range sinks {
		if i > 0 {
			s += ","
		}
		s += k.Name()
	}
	if s == "" {
		return "none"
	}
	return s
}

func reportStats(ctx context.Context, sinks []Sink) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, s := range sinks {
				st := s.Stats()
				logf("sink %s: sent=%d dropped=%d failed=%d duplicates=%d", s.Name(), st.Sent, st.Dropped, st.Failed, st.Duplicates)
			}
		}
	}
}

// drain waits (bounded) until the HTTP sinks have no queued events.
func drain(sinks []Sink) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		busy := false
		for _, s := range sinks {
			switch k := s.(type) {
			case *controllerSink:
				busy = busy || len(k.queue) > 0
			case *apiSink:
				busy = busy || len(k.queue) > 0
			}
		}
		if !busy {
			time.Sleep(1200 * time.Millisecond) // one api flush interval, plus in-flight requests
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
