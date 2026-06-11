package httpd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Serve runs the web UI until ctx is cancelled, then shuts down gracefully.
// With DW_HTTPS off it serves plain HTTP; on, it serves TLS behind a port-sharing
// listener that 301-redirects plaintext requests to https. It returns nil on a
// clean shutdown and a non-nil error on a bind or serve failure.
func (s *Server) Serve(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			slog.Error("web server shutdown", "err", err)
		}
	}()

	if !s.cfg.HTTPS {
		slog.Info("web UI listening", "addr", addr, "tls", false)
		return ignoreClosed(srv.ListenAndServe())
	}

	certFile, keyFile, generated, err := s.resolveUICert()
	if err != nil {
		return err
	}
	if generated {
		slog.Info("generated self-signed UI certificate", "cert", certFile, "fingerprint", certFingerprint(certFile))
	}
	tlsCfg, err := buildTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	listener := newTLSRedirectListener(ln, tlsCfg, strconv.Itoa(s.cfg.Port), s.cfg.Domain, s.cfg.TrustedProxy)
	slog.Info("web UI listening", "addr", addr, "tls", true)
	return ignoreClosed(srv.Serve(listener))
}

func ignoreClosed(err error) error {
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// healthz is the unauthenticated liveness probe: it returns 200 with no body, so
// the dockwatch health command (and the container HEALTHCHECK) can confirm the
// server is serving without exposing any data.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
