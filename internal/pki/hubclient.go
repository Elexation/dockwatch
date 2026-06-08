package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// LoadHubClient loads the hub's client identity (hub.crt + hub.key) and the CA
// trust pool (ca.crt) from dir, for dialing agents over mTLS. ca.crt may hold
// 1..2 CAs during a rollover; all are trusted.
func LoadHubClient(dir string) (tls.Certificate, *x509.CertPool, error) {
	certPath := filepath.Join(dir, hubCertFile)
	keyPath := filepath.Join(dir, hubKeyFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read %s: %w", keyPath, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load hub client cert: %w", err)
	}

	caPath := filepath.Join(dir, caCertFile)
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read %s: %w", caPath, err)
	}
	cas, err := parseCerts(caPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if len(cas) == 0 {
		return tls.Certificate{}, nil, fmt.Errorf("no CA certificate in %s", caPath)
	}
	return cert, NewCertPool(cas), nil
}
