package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"
)

// Leaf is a minted end-entity certificate with its private key.
type Leaf struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// MintHubClient mints the hub's client identity (ExtKeyUsage: ClientAuth).
func (ca *CA) MintHubClient(now time.Time) (*Leaf, error) {
	return ca.mintLeaf(now, leafTemplate{
		commonName: "dockwatch-hub",
		extUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// MintAgentServer mints an agent's server certificate (ExtKeyUsage: ServerAuth)
// with host as its only SAN. host is the IP or DNS name taken from
// DW_AGENT_<NAME>_URL; the hub connects to that host, so the SAN must match it.
func (ca *CA) MintAgentServer(now time.Time, host string) (*Leaf, error) {
	t := leafTemplate{
		commonName: host,
		extUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		t.ips = []net.IP{ip}
	} else {
		t.dns = []string{host}
	}
	return ca.mintLeaf(now, t)
}

type leafTemplate struct {
	commonName string
	extUsage   []x509.ExtKeyUsage
	dns        []string
	ips        []net.IP
}

func (ca *CA) mintLeaf(now time.Time, t leafTemplate) (*Leaf, error) {
	if ca.Key == nil {
		return nil, fmt.Errorf("cannot mint %q: ca.key absent", t.commonName)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: t.commonName},
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  t.extUsage,
		DNSNames:     t.dns,
		IPAddresses:  t.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	return &Leaf{Cert: cert, Key: key}, nil
}
