// Package httpd serves the hub's session-gated web UI: routing, the session gate,
// the setup/login/logout flows, and the HTTP/TLS transport (plain HTTP, or TLS
// behind a port-sharing listener that redirects plaintext requests to https).
package httpd

import (
	"context"
	"io/fs"
	"net/http"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/elexation/dockwatch/internal/web"
)

const (
	sessionCookie = "dw_session"
	themeCookie   = "dw_theme"
	defaultTTL    = 30 * 24 * time.Hour // sliding session lifetime (SPEC 11)
)

// LocalReader is the dashboard's slice of inventory.Reader (an interface for testing).
type LocalReader interface {
	Read(ctx context.Context) (inventory.Inventory, error)
}

// Config carries the server's dependencies and deployment-derived flags.
type Config struct {
	Renderer         *web.Renderer
	Store            *store.Store
	Local            LocalReader
	StaticFS         fs.FS
	LocalName        string // display name for the hub's own host
	NotificationsOff bool   // DW_NTFY_TOPIC unset
	SecureCookie     bool   // DW_HTTPS or DW_TRUSTED_PROXY

	// Check-now wiring into the hub scheduler and poller. Each func is
	// optional: nil degrades its feature (no manual checks, no agent rows)
	// instead of panicking.
	Trigger          func()                       // Scheduler.Trigger
	CheckRunning     func() bool                  // Scheduler.Running
	LastCycleDone    func() time.Time             // Scheduler.LastCycle
	AgentInventories func() []inventory.Inventory // Poller.AgentInventories; last-known, not live

	// Transport (SPEC 12), consumed by Serve.
	Port         int    // listen port
	HTTPS        bool   // DW_HTTPS: serve TLS behind the port-sharing redirect listener
	TLSCert      string // DW_TLS_CERT; empty pairs with TLSKey to mean self-signed
	TLSKey       string // DW_TLS_KEY
	CertsDir     string // DW_CERTS; a self-signed UI cert lives under <CertsDir>/ui
	Domain       string // DW_DOMAIN: canonical host for the https redirect
	TrustedProxy bool   // DW_TRUSTED_PROXY: drops the port from the redirect target

	SessionTTL time.Duration // zero means defaultTTL
	Now        func() time.Time
}

// Server is the hub's web UI handler.
type Server struct {
	cfg Config
	mux *http.ServeMux
	now func() time.Time
	ttl time.Duration
}

// New builds a Server with its routes registered.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ttl := cfg.SessionTTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	s := &Server{cfg: cfg, now: cfg.Now, ttl: ttl}
	s.routes()
	return s
}

func (s *Server) routes() {
	mux := http.NewServeMux()
	// Session-gated pages and the check-now endpoints.
	mux.HandleFunc("GET /{$}", s.requireSession(s.dashboard))
	mux.HandleFunc("GET /agents", s.requireSession(s.agents))
	mux.HandleFunc("POST /check", s.requireSession(s.checkNow))
	mux.HandleFunc("GET /check", s.requireSession(s.checkStatus))
	// Unauthenticated surface.
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /setup", s.setupForm)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /healthz", s.healthz)
	if s.cfg.StaticFS != nil {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.cfg.StaticFS)))
	}
	s.mux = mux
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler { return s.mux }
