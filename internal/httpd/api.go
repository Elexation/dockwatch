package httpd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/web"
)

// apiTriggerCooldown spaces API-triggered checks. It equals the shortest
// DW_INTERVAL the hub accepts, so the API never checks more often than config could.
const apiTriggerCooldown = 5 * time.Minute

// statusResponse is the GET /api/v1/status body. Fields are only ever added;
// a rename or removal needs a new path version.
type statusResponse struct {
	GeneratedAt time.Time      `json:"generated_at"`
	LastCycle   time.Time      `json:"last_cycle,omitzero"` // last cycle this hub process completed
	Checking    bool           `json:"checking"`
	Hosts       []apiHost      `json:"hosts"`
	Counts      map[string]int `json:"counts"` // containers per state
	Containers  []apiContainer `json:"containers"`
}

// apiHost is one watched host. LastSeen is its last successful poll; on an
// unreachable host it dates every row's running version.
type apiHost struct {
	Name      string    `json:"name"`
	Reachable bool      `json:"reachable"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
	Docker    string    `json:"docker,omitempty"` // "ok" or "unavailable", from the last inventory that got through
}

// apiContainer is one dashboard row. CheckedAt dates the registry check, not
// the running version, which a stale row knows only as of its host's LastSeen.
type apiContainer struct {
	Host                 string    `json:"host"`
	Name                 string    `json:"name"`
	Image                string    `json:"image"`
	State                string    `json:"state"`
	Current              string    `json:"current,omitempty"` // update: running version
	Latest               string    `json:"latest,omitempty"`  // update: newest matching version
	Bump                 string    `json:"bump,omitempty"`
	RepublishedAt        time.Time `json:"republished_at,omitzero"`
	RepublishedEstimated bool      `json:"republished_estimated,omitempty"`
	Error                string    `json:"error,omitempty"`
	Health               string    `json:"health,omitempty"`
	CheckedAt            time.Time `json:"checked_at,omitzero"`
	Stale                bool      `json:"stale,omitempty"`
}

// triggerResponse is the POST /api/v1/check body; the triggered cycle is done
// once the status endpoint's last_cycle moves past LastCycle.
type triggerResponse struct {
	LastCycle time.Time `json:"last_cycle,omitzero"`
}

type apiError struct {
	Error string `json:"error"`
}

// requireToken admits only requests bearing the API token. It never redirects
// or touches cookies, so a session alone cannot reach the API.
func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validToken(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="dockwatch"`)
			writeJSON(w, http.StatusUnauthorized, apiError{"missing or invalid API token"})
			return
		}
		next(w, r)
	}
}

// validToken checks the bearer token against the configured hash. It bypasses
// authGuard on purpose: the token is long and random, not a password, and
// sharing login's failure count would let a misconfigured client lock out the operator.
func (s *Server) validToken(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], s.cfg.APITokenSHA256) == 1
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	// Unlike the dashboard, a store error fails the request: an empty answer
	// would read as "nothing to update".
	checks, err := s.cfg.Store.AllChecks()
	if err != nil {
		slog.Error("read checks", "err", err)
		writeJSON(w, http.StatusInternalServerError, apiError{"state store unreadable"})
		return
	}
	agents, err := s.cfg.Store.AllAgents()
	if err != nil {
		slog.Error("read agents", "err", err)
		writeJSON(w, http.StatusInternalServerError, apiError{"state store unreadable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dockerReadTimeout)
	defer cancel()
	local, err := s.cfg.Local.Read(ctx)
	if err != nil {
		slog.Warn("local docker read failed", "err", err)
	}
	remote := s.agentInventories()
	checking := s.checking()
	vm := web.BuildDashboard(append([]inventory.Inventory{local}, remote...), checks, web.DashboardInput{
		LocalName:  s.cfg.LocalName,
		Checking:   checking,
		StaleHosts: staleOf(agents),
	})

	docker := make(map[string]string, len(remote))
	for _, inv := range remote {
		docker[inv.Host] = inv.Docker
	}
	hosts := []apiHost{{Name: local.Host, Reachable: true, Docker: local.Docker}}
	for _, a := range agents {
		hosts = append(hosts, apiHost{Name: a.Name, Reachable: a.LastOK, LastSeen: a.LastSuccess.UTC(), Docker: docker[a.Name]})
	}

	counts := make(map[string]int)
	containers := make([]apiContainer, 0, len(vm.FlatRows))
	for _, row := range vm.FlatRows {
		counts[row.State]++
		containers = append(containers, apiContainer{
			Host:                 row.Host,
			Name:                 row.Name,
			Image:                row.Image,
			State:                row.State,
			Current:              row.From,
			Latest:               row.To,
			Bump:                 row.Bump,
			RepublishedAt:        row.RepublishedAt.UTC(),
			RepublishedEstimated: row.RepublishedEstimated,
			Error:                row.Err,
			Health:               row.Health,
			CheckedAt:            row.Checked.UTC(),
			Stale:                row.Stale,
		})
	}

	writeJSON(w, http.StatusOK, statusResponse{
		GeneratedAt: s.now().UTC(),
		LastCycle:   s.cycleDone().UTC(),
		Checking:    checking,
		Hosts:       hosts,
		Counts:      counts,
		Containers:  containers,
	})
}

// apiCheck starts a full check cycle, at most once per apiTriggerCooldown.
func (s *Server) apiCheck(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Trigger == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{"manual checks unavailable"})
		return
	}
	// The scheduler folds a mid-cycle trigger into the running cycle, whose
	// inventories predate this request, so refuse rather than report success.
	if s.checking() {
		writeJSON(w, http.StatusConflict, apiError{"a check is already running; retry once checking is false"})
		return
	}
	if wait := s.claimTrigger(); wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		msg := fmt.Sprintf("API checks are limited to one per %d minutes; retry in %ds", int(apiTriggerCooldown/time.Minute), secs)
		writeJSON(w, http.StatusTooManyRequests, apiError{msg})
		return
	}
	last := s.cycleDone()
	s.cfg.Trigger()
	writeJSON(w, http.StatusAccepted, triggerResponse{LastCycle: last.UTC()})
}

// claimTrigger records an API trigger and returns 0, or returns how long until
// the cooldown allows one.
func (s *Server) claimTrigger() time.Duration {
	s.apiMu.Lock()
	defer s.apiMu.Unlock()
	now := s.now()
	if !s.apiTriggered.IsZero() {
		if wait := s.apiTriggered.Add(apiTriggerCooldown).Sub(now); wait > 0 {
			return wait
		}
	}
	s.apiTriggered = now
	return 0
}

// writeJSON sends v as an uncacheable JSON response.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write api response", "err", err)
	}
}
