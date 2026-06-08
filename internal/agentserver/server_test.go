package agentserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/elexation/dockwatch/internal/agentserver"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/pki"
)

// fakeDocker satisfies the interface inventory.NewReader accepts, returning an
// empty list so the handler responds without a real daemon. These tests exercise
// transport and routing, not inventory content.
type fakeDocker struct{}

func (fakeDocker) ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error) {
	return client.ContainerListResult{}, nil
}

func (fakeDocker) ImageInspect(context.Context, string, ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	return client.ImageInspectResult{}, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func httpsClient(conf *tls.Config) *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: conf},
	}
}

// startAgent mints a PKI tree in a temp dir and starts the agent on an ephemeral
// loopback port. The agent cert's SAN is 127.0.0.1, so clients dialing the
// returned address verify it. It returns the address, the CA pool and hub client
// cert for building clients, and a stop func.
func startAgent(t *testing.T) (addr string, caPool *x509.CertPool, hubCert tls.Certificate, stop func()) {
	t.Helper()
	dir := t.TempDir()
	if _, err := pki.Bootstrap(dir, []pki.AgentRef{{Name: "test", Host: "127.0.0.1"}}, time.Now()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	hubCert, caPool, err := pki.LoadHubClient(dir)
	if err != nil {
		t.Fatalf("LoadHubClient: %v", err)
	}

	srv, err := agentserver.New(agentserver.Config{
		Addr:       "127.0.0.1:0",
		BundlePath: filepath.Join(dir, "agents", "test", "bundle.pem"),
		Reader:     inventory.NewReader(fakeDocker{}, "testhost"),
		Logger:     quietLogger(),
	})
	if err != nil {
		t.Fatalf("agentserver.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), caPool, hubCert, func() { _ = srv.Close() }
}

func TestAgentTransport(t *testing.T) {
	addr, caPool, hubCert, stop := startAgent(t)
	defer stop()

	// Acceptance 1: plain HTTP serves no data. The TLS-only listener rejects it;
	// Go's stdlib answers a generic 400 ("HTTP request sent to HTTPS server")
	// with no inventory. Either an outright connection error or any non-200 is a
	// correct refusal; a 200 would mean data leaked over plaintext.
	t.Run("plain HTTP serves no data", func(t *testing.T) {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + "/v1/inventory")
		if err != nil {
			return // connection rejected outright
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("plaintext request returned 200; agent must not serve data over plaintext")
		}
	})

	// Acceptance 2: TLS with no client cert fails (RequireAndVerifyClientCert).
	t.Run("no client cert rejected", func(t *testing.T) {
		resp, err := httpsClient(&tls.Config{RootCAs: caPool}).Get("https://" + addr + "/v1/inventory")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("no-cert client got %d, want handshake failure", resp.StatusCode)
		}
	})

	// Acceptance 3: a client cert from a different CA fails.
	t.Run("wrong-CA client cert rejected", func(t *testing.T) {
		otherCA, err := pki.MintCA(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		otherHub, err := otherCA.MintHubClient(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		wrong := tls.Certificate{Certificate: [][]byte{otherHub.Cert.Raw}, PrivateKey: otherHub.Key}
		resp, err := httpsClient(&tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{wrong}}).
			Get("https://" + addr + "/v1/inventory")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("wrong-CA client got %d, want handshake failure", resp.StatusCode)
		}
	})

	// Acceptance 4: a valid hub cert gets inventory on the route, 404 elsewhere,
	// 405 on a non-GET to the route.
	t.Run("valid cert serves inventory", func(t *testing.T) {
		c := httpsClient(&tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{hubCert}})

		resp, err := c.Get("https://" + addr + "/v1/inventory")
		if err != nil {
			t.Fatalf("valid client GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var inv inventory.Inventory
		if err := json.NewDecoder(resp.Body).Decode(&inv); err != nil {
			t.Fatalf("decode inventory: %v", err)
		}
		if inv.V != inventory.WireVersion {
			t.Errorf("inventory v = %d, want %d", inv.V, inventory.WireVersion)
		}
		if inv.Host != "testhost" {
			t.Errorf("inventory host = %q, want testhost", inv.Host)
		}

		nf, err := c.Get("https://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		nf.Body.Close()
		if nf.StatusCode != http.StatusNotFound {
			t.Errorf("/healthz status = %d, want 404", nf.StatusCode)
		}

		req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/inventory", nil)
		post, err := c.Do(req)
		if err != nil {
			t.Fatalf("POST /v1/inventory: %v", err)
		}
		post.Body.Close()
		if post.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST status = %d, want 405", post.StatusCode)
		}
	})
}

// Acceptance 5: a missing or unparseable bundle is a fatal startup error
// (returned here; main turns it into a non-zero exit).
func TestNewRejectsBadBundle(t *testing.T) {
	reader := inventory.NewReader(fakeDocker{}, "h")

	if _, err := agentserver.New(agentserver.Config{
		Addr:       "127.0.0.1:0",
		BundlePath: filepath.Join(t.TempDir(), "nope.pem"),
		Reader:     reader,
		Logger:     quietLogger(),
	}); err == nil {
		t.Error("expected error for missing bundle")
	}

	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agentserver.New(agentserver.Config{
		Addr:       "127.0.0.1:0",
		BundlePath: bad,
		Reader:     reader,
		Logger:     quietLogger(),
	}); err == nil {
		t.Error("expected error for unparseable bundle")
	}
}
