package httpd

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	uiCertValidity   = 10 * 365 * 24 * time.Hour
	uiCertBackdate   = 24 * time.Hour
	peekReadDeadline = 5 * time.Second
)

// resolveUICert returns the cert and key paths for the UI TLS listener.
// Operator-provided DW_TLS_CERT/DW_TLS_KEY are used as-is; otherwise a self-signed
// pair under <CertsDir>/ui is generated, and regenerated once expired. The bool
// reports whether this call wrote a fresh self-signed pair.
func (s *Server) resolveUICert() (certFile, keyFile string, generated bool, err error) {
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return s.cfg.TLSCert, s.cfg.TLSKey, false, nil
	}
	dir := filepath.Join(s.cfg.CertsDir, "ui")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", false, fmt.Errorf("create ui cert dir: %w", err)
	}
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	generated, err = ensureSelfSignedCert(certFile, keyFile, s.now())
	return certFile, keyFile, generated, err
}

// ensureSelfSignedCert writes a self-signed ECDSA P-256 server certificate to
// certFile/keyFile when either file is missing or the existing certificate has
// expired, reporting whether it wrote a fresh pair. SANs cover localhost, the
// hostname, and every non-loopback interface address.
func ensureSelfSignedCert(certFile, keyFile string, now time.Time) (bool, error) {
	if !certNeedsGen(certFile, keyFile, now) {
		return false, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, fmt.Errorf("generate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return false, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dockwatch"},
		NotBefore:    now.Add(-uiCertBackdate),
		NotAfter:     now.Add(uiCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipNet.IP)
			}
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return false, fmt.Errorf("create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeFileAtomic(certFile, certPEM, 0o644); err != nil {
		return false, fmt.Errorf("write cert: %w", err)
	}
	if err := writeFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return false, fmt.Errorf("write key: %w", err)
	}
	return true, nil
}

// certNeedsGen reports whether a fresh self-signed pair must be written: a missing
// key or cert, or an unreadable, unparseable, or expired existing certificate.
func certNeedsGen(certFile, keyFile string, now time.Time) bool {
	if _, err := os.Stat(keyFile); err != nil {
		return true
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return !now.Before(cert.NotAfter)
}

// writeFileAtomic writes data to a temp file in the destination directory and
// renames it into place, so a reader never sees a partial file and the mode lands
// atomically with the name.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// buildTLSConfig loads the UI cert/key into a TLS 1.3 server config. ALPN
// advertises h2 then http/1.1; the listener uses srv.Serve, so a client that does
// not negotiate h2 falls back to http/1.1.
func buildTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert/key: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{cert},
	}, nil
}

// certFingerprint returns the SHA-256 fingerprint of the certificate in certFile,
// or "unknown" if it cannot be read or parsed.
func certFingerprint(certFile string) string {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return "unknown"
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "unknown"
	}
	sum := sha256.Sum256(block.Bytes)
	return fmt.Sprintf("SHA256:%X", sum)
}

// tlsRedirectListener fronts a TCP listener and shares one port: a connection
// whose first byte is the TLS handshake record (0x16) is surfaced through Accept
// as a TLS server conn, while a plaintext HTTP connection is answered inline with
// a 301 to the https URL and never reaches the http.Server.
type tlsRedirectListener struct {
	net.Listener
	tlsCfg       *tls.Config
	port         string
	domain       string
	trustedProxy bool

	conns     chan net.Conn
	errs      chan error
	closeOnce sync.Once
	closed    chan struct{}
}

func newTLSRedirectListener(ln net.Listener, cfg *tls.Config, port, domain string, trustedProxy bool) net.Listener {
	l := &tlsRedirectListener{
		Listener:     ln,
		tlsCfg:       cfg,
		port:         port,
		domain:       domain,
		trustedProxy: trustedProxy,
		conns:        make(chan net.Conn),
		errs:         make(chan error, 1),
		closed:       make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

// acceptLoop accepts raw connections and hands each to its own dispatch goroutine,
// so one stalled client cannot head-of-line block the accept path for everyone.
func (l *tlsRedirectListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errs <- err:
			case <-l.closed:
				return
			}
			// http.Server.Serve backs off and retries on temporary errors
			// (e.g. EMFILE); keep accepting so its retry finds a live loop.
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return
		}
		go l.dispatch(conn)
	}
}

// dispatch reads the first byte (bounded by a deadline) to decide between TLS and
// plaintext HTTP, then either queues the TLS conn for Accept or answers the HTTP
// redirect inline.
func (l *tlsRedirectListener) dispatch(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(peekReadDeadline))
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	pc := newPrefixConn(conn, buf[:])
	if buf[0] != 0x16 {
		redirectHTTP(pc, l.port, l.domain, l.trustedProxy)
		return
	}
	select {
	case l.conns <- tls.Server(pc, l.tlsCfg):
	case <-l.closed:
		conn.Close()
	}
}

func (l *tlsRedirectListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case err := <-l.errs:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *tlsRedirectListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// redirectHTTP answers a single plaintext HTTP request with a 301 to its https
// equivalent, preferring the canonical domain when set. With a trusted proxy or
// the standard 443 port the port is omitted from the target.
func redirectHTTP(conn net.Conn, port, domain string, trustedProxy bool) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(peekReadDeadline))

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	host := req.Host
	if host == "" {
		return
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if domain != "" {
		host = domain
	}

	var target string
	if trustedProxy || port == "443" {
		target = "https://" + host + req.URL.RequestURI()
	} else {
		target = "https://" + net.JoinHostPort(host, port) + req.URL.RequestURI()
	}
	body := "Redirecting to " + target + "\n"
	fmt.Fprintf(conn, "HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", target, len(body), body)
}

// prefixConn re-prepends bytes already read off a conn (the peeked first byte) so
// the wrapped reader sees the original stream intact.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func newPrefixConn(c net.Conn, prefix []byte) *prefixConn {
	buf := make([]byte, len(prefix))
	copy(buf, prefix)
	return &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(buf), c)}
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }
