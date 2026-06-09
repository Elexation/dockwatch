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
	"github.com/elexation/dockwatch/internal/hub"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/pki"
	"github.com/elexation/dockwatch/internal/registry"
	"github.com/elexation/dockwatch/internal/store"
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
	refs := make([]pki.AgentRef, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		u, err := url.Parse(a.URL) // already validated in config.Load
		if err != nil {
			slog.Error("invalid agent URL", "agent", a.Name, "err", err)
			os.Exit(1)
		}
		refs = append(refs, pki.AgentRef{Name: a.Name, Host: u.Hostname()})
	}

	events, err := pki.Bootstrap(cfg.CertsDir, refs, time.Now())
	for _, e := range events {
		logEvent(e)
	}
	if err != nil {
		slog.Error("PKI bootstrap failed", "err", err)
		os.Exit(1)
	}
	slog.Info("PKI bootstrap complete", "certs", cfg.CertsDir)

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	cli, err := inventory.DialDocker(cfg.DockerSock)
	if err != nil {
		slog.Error("docker client init failed", "err", err)
		os.Exit(1)
	}
	local := inventory.NewReader(cli, cfg.LocalName)

	logger := slog.Default()
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
		for _, e := range ev {
			logEvent(e)
		}
		if rerr != nil {
			slog.Error("cert renewal failed", "err", rerr)
		}
	}

	p := hub.NewPoller(local, agents, client, st, logger)
	sched := hub.NewScheduler(p, registry.New(), st, logger, cfg.Interval, renew)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("hub running", "interval", cfg.Interval, "agents", len(agents))
	sched.Run(ctx)
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
