package main

import (
	"context"
	"fmt"
	"log/slog"
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
		os.Exit(0)
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
		slog.Warn("DW_RESET_ADMIN set: wiping admin account and all sessions; re-run first-run setup promptly")
		if err := st.DeleteAdmin(); err != nil {
			slog.Error("reset admin", "err", err)
			os.Exit(1)
		}
		if err := st.ClearSessions(); err != nil {
			slog.Error("clear sessions", "err", err)
			os.Exit(1)
		}
	}

	// Build the notifier before Bootstrap so a startup cert renewal/remint can
	// notify. It no-ops when DW_NTFY_TOPIC is unset, so building it is always safe.
	ntfy := notify.NewClient(cfg.NtfyURL, cfg.NtfyTopic, cfg.NtfyToken, nil)
	notifier := notify.NewNotifier(ntfy, st, logger, cfg.Domain, stagedExpiry(cfg.CertsDir))

	events, err := pki.Bootstrap(cfg.CertsDir, refs, time.Now())
	handleCertEvents(context.Background(), events, notifier)
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
		handleCertEvents(context.Background(), ev, notifier)
		if rerr != nil {
			slog.Error("cert renewal failed", "err", rerr)
		}
	}

	p := hub.NewPoller(local, agents, client, st, logger)
	sched := hub.NewScheduler(p, registry.New(), st, logger, cfg.Interval, renew, notifier)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Web UI over plain HTTP; TLS is layered on separately.
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
	})
	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           webSrv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			slog.Error("web server shutdown", "err", err)
		}
	}()
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("web UI listening", "addr", httpSrv.Addr)
		err := httpSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			stop() // a bind failure brings the whole hub down
		}
		serveErr <- err
	}()

	slog.Info("hub running", "interval", cfg.Interval, "agents", len(agents))
	sched.Run(ctx)

	if err := <-serveErr; err != nil && err != http.ErrServerClosed {
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

	// A hostname-lookup failure is non-fatal: the hub overrides this name from the agent URL anyway.
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
// needed.
func handleCertEvents(ctx context.Context, events []pki.Event, n *notify.Notifier) {
	for _, e := range events {
		logEvent(e)
		switch e.Kind {
		case pki.Renewed:
			if e.Name != "" {
				n.NotifyBundleRenewed(ctx, e.Name)
			}
		case pki.RemintedSAN:
			n.NotifyBundleRemintedSAN(ctx, e.Name)
		case pki.CAKeyMissing:
			n.NotifyCAKeyMissing(ctx, e.Detail)
		}
	}
}

func logEvent(e pki.Event) {
	attrs := []any{"event", string(e.Kind)}
	if e.Name != "" {
		attrs = append(attrs, "agent", e.Name)
	}
	switch e.Kind {
	case pki.CAKeyMissing, pki.OrphanedAgent, pki.RemintedSAN, pki.Renewed:
		slog.Warn(e.Msg, attrs...)
	default:
		slog.Info(e.Msg, attrs...)
	}
}
