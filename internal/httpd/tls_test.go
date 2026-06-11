package httpd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	gen, err := ensureSelfSignedCert(certFile, keyFile, now)
	if err != nil {
		t.Fatalf("first gen: %v", err)
	}
	if !gen {
		t.Fatal("first call did not report a generated cert")
	}

	cert := parseCertFile(t, certFile)
	if cert.NotAfter.Sub(cert.NotBefore) < 9*365*24*time.Hour {
		t.Errorf("validity too short: %s .. %s", cert.NotBefore, cert.NotAfter)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", cert.ExtKeyUsage)
	}
	if !hasDNS(cert.DNSNames, "localhost") {
		t.Errorf("DNSNames = %v, want to include localhost", cert.DNSNames)
	}
	if len(cert.IPAddresses) == 0 {
		t.Error("no IP SANs, want at least the loopback addresses")
	}

	// A still-valid cert is left untouched.
	if gen, err := ensureSelfSignedCert(certFile, keyFile, now); err != nil || gen {
		t.Errorf("second call: gen=%v err=%v, want gen=false", gen, err)
	}

	// An expired cert is regenerated.
	if gen, err := ensureSelfSignedCert(certFile, keyFile, cert.NotAfter.Add(time.Hour)); err != nil || !gen {
		t.Errorf("expired call: gen=%v err=%v, want gen=true", gen, err)
	}
}

func TestBuildTLSConfig(t *testing.T) {
	certFile, keyFile := genTestCert(t)
	cfg, err := buildTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS1.3", cfg.MinVersion)
	}
	if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "h2" {
		t.Errorf("NextProtos = %v, want h2 first", cfg.NextProtos)
	}
}

func TestCertFingerprint(t *testing.T) {
	if fp := certFingerprint(filepath.Join(t.TempDir(), "missing.crt")); fp != "unknown" {
		t.Errorf("missing cert fingerprint = %q, want unknown", fp)
	}
	certFile, _ := genTestCert(t)
	if fp := certFingerprint(certFile); len(fp) < 7 || fp[:7] != "SHA256:" {
		t.Errorf("fingerprint = %q, want a SHA256: prefix", fp)
	}
}

func TestTLSRedirectListener(t *testing.T) {
	certFile, keyFile := genTestCert(t)
	tlsCfg, err := buildTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(raw.Addr().String())
	ln := newTLSRedirectListener(raw, tlsCfg, port, "", false)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	base := "127.0.0.1:" + port

	// A plaintext request is redirected, never served.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.Get("http://" + base + "/dash")
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("plain status = %d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://"+base+"/dash" {
		t.Errorf("Location = %q, want https://%s/dash", loc, base)
	}

	// A TLS request is served.
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp2, err := tlsClient.Get("https://" + base + "/dash")
	if err != nil {
		t.Fatalf("tls GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("tls status = %d, want 200", resp2.StatusCode)
	}
}

func TestResolveUICert(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{CertsDir: dir})
	certFile, keyFile, generated, err := s.resolveUICert()
	if err != nil {
		t.Fatalf("resolveUICert: %v", err)
	}
	if !generated {
		t.Error("first call did not generate a self-signed pair")
	}
	if got := filepath.Dir(certFile); got != filepath.Join(dir, "ui") {
		t.Errorf("cert dir = %q, want %q", got, filepath.Join(dir, "ui"))
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert not written: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("key not written: %v", err)
	}

	// Operator-provided cert/key are returned verbatim; nothing is generated.
	s2 := New(Config{CertsDir: dir, TLSCert: "/x/c.pem", TLSKey: "/x/k.pem"})
	c, k, gen, err := s2.resolveUICert()
	if err != nil || gen || c != "/x/c.pem" || k != "/x/k.pem" {
		t.Errorf("operator certs: c=%q k=%q gen=%v err=%v, want passthrough", c, k, gen, err)
	}
}

func TestHealthzUnauthenticated(t *testing.T) {
	s, _ := newTestServer(t, false)
	if rec := do(s, "GET", "/healthz", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz: code=%d, want 200", rec.Code)
	}
}

func genTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if _, err := ensureSelfSignedCert(certFile, keyFile, time.Now()); err != nil {
		t.Fatalf("ensureSelfSignedCert: %v", err)
	}
	return certFile, keyFile
}

func parseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func hasDNS(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
