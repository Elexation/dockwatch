package agentserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
)

// dockerReadTimeout bounds the Docker read below the hub's 10s poll timeout and
// the 10s write timeout, so a hung daemon still answers docker: unavailable.
const dockerReadTimeout = 7 * time.Second

// newHandler builds the agent's single-route mux. The method-qualified pattern
// makes every other path a 404 and any method other than GET or HEAD a 405
// (ServeMux matches HEAD against a GET pattern), so the only reachable surface
// is reading the inventory.
func newHandler(reader *inventory.Reader, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dockerReadTimeout)
		defer cancel()
		inv, err := reader.Read(ctx)
		if err != nil {
			// Daemon-down is already encoded as docker: unavailable in inv, so log it
			// but still return 200 (distinguishes agent-up/docker-down from agent-down).
			logger.Warn("docker read degraded", "err", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(inv); err != nil {
			logger.Error("encode inventory response", "err", err)
		}
	})
	return mux
}
