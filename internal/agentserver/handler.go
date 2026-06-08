package agentserver

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/elexation/dockwatch/internal/inventory"
)

// newHandler builds the agent's single-route mux. The method-qualified pattern
// makes a non-GET request to the route a 405 and every other path a 404, so no
// surface beyond GET /v1/inventory is reachable.
func newHandler(reader *inventory.Reader, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		inv, err := reader.Read(r.Context())
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
