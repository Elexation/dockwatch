package main

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/elexation/dockwatch/internal/agentserver"
	"github.com/elexation/dockwatch/internal/config"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/pki"
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

// runHub runs the PKI bootstrap (minting whatever certs are missing), then
// idles. The hub core (scheduler, registry, notifications, web) is not built
// yet; until it is, the process idles so the container stays up.
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
	select {} // idle; Docker's SIGTERM still terminates the process
}

func runAgent(cfg *config.Config) {
	cli, err := inventory.DialDocker(cfg.DockerSock)
	if err != nil {
		slog.Error("docker client init failed", "err", err)
		os.Exit(1)
	}

	// The agent reports its OS hostname; the hub overrides the display name from
	// DW_AGENT_<NAME>_URL, so a hostname lookup failure degrades to a placeholder
	// rather than refusing to serve.
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
