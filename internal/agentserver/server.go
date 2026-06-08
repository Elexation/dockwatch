// Package agentserver implements DockWatch's agent role: an mTLS-only HTTP
// server exposing exactly one route, GET /v1/inventory. It holds no state, makes
// no outbound connections, and reads its Docker socket read-only. Transport is
// fixed at TLS 1.3 with required-and-verified client certs; there is no env to
// disable or downgrade it.
package agentserver

import (
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/pki"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 8 << 10 // 8 KiB; the one request has a tiny header
	maxConns          = 5       // legitimate load is one hub; the rest is abuse

	handshakeLogWindow = time.Minute
	handshakeLogMax    = 5 // detailed handshake-error lines per window before summarizing
)

// Server is the agent's mTLS HTTP server.
type Server struct {
	addr      string
	tlsConfig *tls.Config
	http      *http.Server
}

// Config configures the agent server.
type Config struct {
	Addr       string            // listen address, e.g. ":7443"
	BundlePath string            // path to bundle.pem (agent cert + key + CA)
	Reader     *inventory.Reader // produces the inventory served at /v1/inventory
	Logger     *slog.Logger      // nil uses slog.Default()
}

// New validates the bundle and builds the agent server. A missing or
// unparseable bundle is returned as a fatal startup error (the caller logs and
// exits non-zero); there is no certless or plaintext fallback.
func New(cfg Config) (*Server, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	pemBytes, err := os.ReadFile(cfg.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("read bundle %s: %w", cfg.BundlePath, err)
	}
	bundle, err := pki.ParseBundle(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse bundle %s: %w", cfg.BundlePath, err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    bundle.ClientCAPool(),
		Certificates: []tls.Certificate{bundle.TLSCert},
	}

	httpSrv := &http.Server{
		Handler:           newHandler(cfg.Reader, logger),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(&handshakeLogWriter{logger: logger}, "", 0),
	}

	return &Server{addr: cfg.Addr, tlsConfig: tlsConfig, http: httpSrv}, nil
}

// ListenAndServe listens on the configured address and serves until error.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
	return s.Serve(ln)
}

// Serve caps concurrent connections, wraps ln in TLS, and serves. It is exposed
// so tests can supply an ephemeral-port listener.
func (s *Server) Serve(ln net.Listener) error {
	ln = netutil.LimitListener(ln, maxConns)
	return s.http.Serve(tls.NewListener(ln, s.tlsConfig))
}

// Close stops the server and its listener.
func (s *Server) Close() error {
	return s.http.Close()
}

// handshakeLogWriter rate-limits TLS-handshake-error lines from http.Server's
// ErrorLog so a misconfigured or scanning client surfaces as periodic log noise,
// never a flood and never silence. Other error lines pass through unchanged.
type handshakeLogWriter struct {
	logger *slog.Logger

	mu          sync.Mutex
	windowStart time.Time
	emitted     int
	suppressed  int
}

func (w *handshakeLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	if !strings.Contains(line, "TLS handshake error") {
		w.logger.Warn(line)
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if now.Sub(w.windowStart) >= handshakeLogWindow {
		if w.suppressed > 0 {
			w.logger.Warn("suppressed additional TLS handshake errors", "count", w.suppressed)
		}
		w.windowStart = now
		w.emitted = 0
		w.suppressed = 0
	}
	if w.emitted < handshakeLogMax {
		w.logger.Warn(line)
		w.emitted++
	} else {
		w.suppressed++
	}
	return len(p), nil
}
