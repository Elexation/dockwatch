package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/elexation/dockwatch/internal/config"
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

	// Role servers (agent §6, hub §7) arrive in later phases.
	slog.Error("role not yet implemented", "mode", cfg.Mode)
	os.Exit(1)
}
