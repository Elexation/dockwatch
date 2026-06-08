package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// NewCertPool builds a trust pool from 1..2 CA certs (the second present only
// during a CA rollover).
func NewCertPool(cas []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range cas {
		pool.AddCert(ca)
	}
	return pool
}

// verifyKeyPossession confirms key is the private half of cert's public key.
func verifyKeyPossession(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is %T, want ECDSA", cert.PublicKey)
	}
	if !key.PublicKey.Equal(pub) {
		return fmt.Errorf("private key does not match certificate")
	}
	return nil
}

// verifyChain checks that leaf chains to a CA in pool, is valid at now, and
// satisfies usage.
func verifyChain(leaf *x509.Certificate, pool *x509.CertPool, usage x509.ExtKeyUsage, now time.Time) error {
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{usage},
	})
	return err
}

// sanMatches reports whether cert's SANs include host (matched as an IP if host
// parses as one, otherwise as a DNS name).
func sanMatches(cert *x509.Certificate, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		for _, cip := range cert.IPAddresses {
			if cip.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, dns := range cert.DNSNames {
		if dns == host {
			return true
		}
	}
	return false
}
