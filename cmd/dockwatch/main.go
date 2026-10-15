package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/elexation/dockwatch/internal/agentserver"
	"github.com/elexation/dockwatch/internal/config"
	"github.com/elexation/dockwatch/internal/httpd"
	"github.com/elexation/dockwatch/internal/hub"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/notify"
	"github.com/elexation/dockwatch/internal/pki"
	"github.com/elexation/dockwatch/internal/registry"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/elexation/dockwatch/internal/web"
)

// Overridden via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "version":
		fmt.Printf("dockwatch %s (commit %s, built %s)\n", version, commit, date)
	case "health":
		health()
	case "run":
		run()
	default:
		fmt.Fprintf(os.Stderr, "dockwatch: unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func run() {
	cfg, warns, err := config.Load(os.Environ())
	for _, w := range warns {
		slog.Warn(w)
	}
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded",
		"mode", cfg.Mode,
		"port", cfg.Port,
		"agents", len(cfg.Agents),
	)

	switch cfg.Mode {
	case "hub":
		runHub(cfg)
	case "agent":
		runAgent(cfg)
	}
}

// health is the container HEALTHCHECK command: it confirms this process
// is serving and exits 0 on success, non-zero otherwise. The hub pings its own
// /healthz over loopback; the agent, which exposes only an mTLS route, is probed
// by a bare TCP connect to its listener.
func health() {
	cfg, _, err := config.Load(os.Environ())
	if err != nil {
		os.Exit(1)
	}

	if cfg.IsAgent() {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Port), 5*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	scheme := "http"
	client := &http.Client{Timeout: 5 * time.Second}
	if cfg.HTTPS {
		scheme = "https"
		// Loopback self-probe of our own (often self-signed) UI cert; it carries no
		// secret and reads no body, so chain verification adds nothing here.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/healthz", scheme, cfg.Port))
	if err != nil {
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

// runHub bootstraps the PKI, then runs the check scheduler until a termination
// signal; a missing hub client identity degrades the hub to local-only.
func runHub(cfg *config.Config) {
	logger := slog.Default()

	refs := make([]pki.AgentRef, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		u, err := url.Parse(a.URL) // already validated in config.Load
		if err != nil {
			slog.Error("invalid agent URL", "agent", a.Name, "err", err)
			os.Exit(1)
		}
		refs = append(refs, pki.AgentRef{Name: a.Name, Host: u.Hostname()})
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// DW_RESET_ADMIN: wipe the admin and all sessions, re-arming first-run setup.
	if cfg.ResetAdmin {
		slog.Warn("DW_RESET_ADMIN set: wiping admin account and all sessions; re-run first-run setup promptly, then unset DW_RESET_ADMIN and recreate the container (a plain restart keeps it set), or every start wipes the account again")
		if err := st.DeleteAdmin(); err != nil {
			slog.Error("reset admin", "err", err)
			os.Exit(1)
		}
		if err := st.ClearSessions(); err != nil {
			slog.Error("clear sessions", "err", err)
			os.Exit(1)
		}
	}

	// Setup is open to whoever reaches the port first, so say so on every start.
	// On a genuine first run this is the prompt; afterwards it is the signal that
	// something (a deleted database, DW_RESET_ADMIN) reopened it.
	if exists, aerr := st.AdminExists(); aerr != nil {
		slog.Error("read admin account", "err", aerr)
		os.Exit(1)
	} else if !exists {
		slog.Warn("no admin account: first-run setup is open on this port until one is created")
	}

	// Config is the source of truth for which agents exist; stored status for a
	// renamed or removed one would otherwise linger on the agents page and keep
	// being evaluated for down alerts.
	names := make([]string, 0, len(cfg.Agents))
	noDownAlert := make(map[string]bool)
	for _, a := range cfg.Agents {
		names = append(names, a.Name)
		if !a.DownAlert {
			noDownAlert[a.Name] = true
			slog.Info("unreachable alert disabled", "agent", a.Name)
		}
	}
	if dropped, perr := st.PruneAgents(names); perr != nil {
		slog.Warn("prune stored agent status", "err", perr)
	} else {
		for _, n := range dropped {
			slog.Info("dropped stored status for agent no longer configured", "agent", n)
		}
	}

	// Checks and notify-once state are keyed by canonical ref (inventory.Ref).
	// Records under any other spelling are never read again, so drop them and
	// say so: the affected images may notify once more, which the state policy
	// accepts in place of a migration.
	canonical := func(ref string) bool { return inventory.Ref(ref) == ref }
	droppedChecks, cerr := st.PruneChecks(canonical)
	droppedNotified, nerr := st.PruneNotified(canonical)
	switch {
	case cerr != nil || nerr != nil:
		slog.Warn("drop records under non-canonical image names", "checks_err", cerr, "notified_err", nerr)
	case droppedChecks+droppedNotified > 0:
		slog.Info("dropped records stored under a non-canonical image name; those images may notify once more",
			"checks", droppedChecks, "notified", droppedNotified)
	}

	// Build the notifier before Bootstrap so a startup cert renewal/remint can
	// notify. It no-ops when DW_NTFY_TOPIC is unset, so building it is always safe.
	ntfy := notify.NewClient(cfg.NtfyURL, cfg.NtfyTopic, cfg.NtfyToken, nil)
	notifier := notify.NewNotifier(ntfy, st, logger, cfg.Domain, stagedExpiry(cfg.CertsDir), noDownAlert)

	events, err := pki.Bootstrap(cfg.CertsDir, refs, time.Now())
	handleCertEvents(context.Background(), events, err == nil, notifier, st)
	if err != nil {
		slog.Error("PKI bootstrap failed", "err", err)
		os.Exit(1)
	}
	slog.Info("PKI bootstrap complete", "certs", cfg.CertsDir)

	cli, err := inventory.DialDocker(cfg.DockerSock)
	if err != nil {
		slog.Error("docker client init failed", "err", err)
		os.Exit(1)
	}
	local := inventory.NewReader(cli, cfg.LocalName)

	var client *http.Client
	agents := make([]hub.Agent, 0, len(cfg.Agents))
	if len(cfg.Agents) > 0 {
		cert, pool, lerr := pki.LoadHubClient(cfg.CertsDir)
		if lerr != nil {
			slog.Error("load hub client identity; running local-only", "err", lerr)
		} else {
			client = hub.NewClient(cert, pool)
			for _, a := range cfg.Agents {
				agents = append(agents, hub.Agent{Name: a.Name, URL: a.URL})
			}
		}
	}

	// renew re-runs the startup minting/renewal rules; the scheduler calls it daily.
	renew := func() {
		ev, rerr := pki.Bootstrap(cfg.CertsDir, refs, time.Now())
		handleCertEvents(context.Background(), ev, rerr == nil, notifier, st)
		if rerr != nil {
			slog.Error("cert renewal failed", "err", rerr)
		}
	}

	p := hub.NewPoller(local, agents, client, st, logger)
	sched := hub.NewScheduler(p, registry.New(), st, logger, cfg.Interval, renew, notifier)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Web UI: plain HTTP, or TLS behind a port-sharing redirect listener.
	renderer, err := web.NewRenderer()
	if err != nil {
		slog.Error("init web renderer", "err", err)
		os.Exit(1)
	}
	staticFS, err := web.StaticFS()
	if err != nil {
		slog.Error("init web static assets", "err", err)
		os.Exit(1)
	}
	webSrv := httpd.New(httpd.Config{
		Renderer:         renderer,
		Store:            st,
		Local:            local,
		StaticFS:         staticFS,
		LocalName:        cfg.LocalName,
		NotificationsOff: cfg.NtfyTopic == "",
		SecureCookie:     cfg.HTTPS || cfg.TrustedProxy,
		Trigger:          sched.Trigger,
		CheckRunning:     sched.Running,
		LastCycleDone:    sched.LastCycle,
		AgentInventories: p.AgentInventories,
		Port:             cfg.Port,
		HTTPS:            cfg.HTTPS,
		TLSCert:          cfg.TLSCert,
		TLSKey:           cfg.TLSKey,
		CertsDir:         cfg.CertsDir,
		Domain:           cfg.Domain,
		TrustedProxy:     cfg.TrustedProxy,
	})
	serveErr := make(chan error, 1)
	go func() {
		err := webSrv.Serve(ctx)
		if err != nil {
			stop() // a bind or serve failure brings the whole hub down
		}
		serveErr <- err
	}()

	slog.Info("hub running", "interval", cfg.Interval, "agents", len(agents))
	sched.Run(ctx)

	if err := <-serveErr; err != nil {
		slog.Error("web server failed", "err", err)
		os.Exit(1)
	}
}

func runAgent(cfg *config.Config) {
	cli, err := inventory.DialDocker(cfg.DockerSock)
	if err != nil {
		slog.Error("docker client init failed", "err", err)
		os.Exit(1)
	}

	// A hostname-lookup failure is non-fatal: the hub replaces this name with the agent's configured name anyway.
	host, err := os.Hostname()
	if err != nil {
		slog.Warn("hostname lookup failed; using placeholder", "err", err)
		host = "agent"
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv, err := agentserver.New(agentserver.Config{
		Addr:       addr,
		BundlePath: filepath.Join(cfg.CertsDir, "bundle.pem"),
		Reader:     inventory.NewReader(cli, host),
	})
	if err != nil {
		slog.Error("agent startup failed", "err", err)
		os.Exit(1)
	}

	slog.Info("agent listening", "addr", addr, "host", host, "sock", cfg.DockerSock)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("agent server stopped", "err", err)
		os.Exit(1)
	}
}

// stagedExpiry returns a closure giving an agent's on-disk bundle leaf expiry.
// Any read or parse failure reports ok=false, disabling the reminder for that
// agent rather than guessing.
func stagedExpiry(certsDir string) func(agent string) (time.Time, bool) {
	return func(agent string) (time.Time, bool) {
		pem, err := os.ReadFile(filepath.Join(certsDir, "agents", agent, "bundle.pem"))
		if err != nil {
			return time.Time{}, false
		}
		b, err := pki.ParseBundle(pem)
		if err != nil {
			return time.Time{}, false
		}
		return b.Cert.NotAfter, true
	}
}

// handleCertEvents logs every PKI event and turns the agent-facing ones into
// notifications. The hub's own client-cert renewal (Name=="") stays log-only:
// agents verify the CA chain, not the specific cert, so no operator action is
// needed. CA-key-missing is a standing condition rather than a one-off event,
// re-emitted by every daily renewal pass while the key is away, so it is
// collapsed into one message and gated on stored state. complete is false when
// Bootstrap stopped on an error before reaching every agent; such a pass cannot
// prove the condition cleared, so it never clears the gate.
func handleCertEvents(ctx context.Context, events []pki.Event, complete bool, n *notify.Notifier, st *store.Store) {
	var caKeyMissing []string
	for _, e := range events {
		logEvent(e)
		switch e.Kind {
		case pki.Renewed:
			if e.Name != "" {
				n.NotifyBundleRenewed(ctx, e.Name, time.Now())
			}
		case pki.RemintedSAN, pki.RemintedCA:
			n.NotifyBundleReissued(ctx, e.Name)
		case pki.CAKeyMissing:
			caKeyMissing = append(caKeyMissing, e.Detail)
		}
	}

	notified, err := st.CAKeyMissingNotified()
	if err != nil {
		slog.Warn("read ca-key-missing gate", "err", err)
		return
	}
	switch {
	case len(caKeyMissing) > 0 && !notified:
		if n.NotifyCAKeyMissing(ctx, caKeyMissing) {
			if serr := st.SetCAKeyMissingNotified(true); serr != nil {
				slog.Warn("persist ca-key-missing gate", "err", serr)
			}
		}
	case len(caKeyMissing) == 0 && notified && complete:
		if serr := st.SetCAKeyMissingNotified(false); serr != nil {
			slog.Warn("clear ca-key-missing gate", "err", serr)
		}
	}
}

func logEvent(e pki.Event) {
	attrs := []any{"event", string(e.Kind)}
	if e.Name != "" {
		attrs = append(attrs, "agent", e.Name)
	}
	switch e.Kind {
	case pki.CAKeyMissing, pki.OrphanedAgent, pki.RemintedSAN, pki.RemintedCA, pki.Renewed:
		slog.Warn(e.Msg, attrs...)
	default:
		slog.Info(e.Msg, attrs...)
	}
}
