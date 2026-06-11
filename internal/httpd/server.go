// Package httpd serves the hub's session-gated web UI over plain HTTP: routing,
// the session gate, and the setup/login/logout flows. TLS is layered on separately.
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
	LocalName        string        // display name for the hub's own host
	NotificationsOff bool          // DW_NTFY_TOPIC unset
	SecureCookie     bool          // DW_HTTPS or DW_TRUSTED_PROXY
	SessionTTL       time.Duration // zero means defaultTTL
	Now              func() time.Time
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
	// Session-gated pages.
	mux.HandleFunc("GET /{$}", s.requireSession(s.dashboard))
	mux.HandleFunc("GET /agents", s.requireSession(s.agents))
	// Unauthenticated surface.
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /setup", s.setupForm)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	if s.cfg.StaticFS != nil {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.cfg.StaticFS)))
	}
	s.mux = mux
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler { return s.mux }
