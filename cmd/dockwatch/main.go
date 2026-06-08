package main

import (
	"fmt"
	"os"
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
		fmt.Fprintln(os.Stderr, "dockwatch: not yet implemented")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "dockwatch: unknown command %q\n", cmd)
		os.Exit(2)
	}
}
