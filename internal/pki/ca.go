// Package pki implements DockWatch's certificate authority and leaf-cert
// minting, agent bundle read/write, verification, and renewal. It is the trust
// core shared by the hub (which mints) and the agent (which consumes a bundle).
//
// All keys are ECDSA P-256; certificate signatures are ECDSA-with-SHA-256. The
// CA is valid 20 years, leaves 10 years; every cert backdates NotBefore by 24h
// for clock-skew tolerance. Private keys and bundles are written 0600.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	caValidity   = 20 * 365 * 24 * time.Hour // ~20 years
	leafValidity = 10 * 365 * 24 * time.Hour // ~10 years
	backdate     = 24 * time.Hour            // NotBefore clock-skew tolerance
	renewWindow  = 90 * 24 * time.Hour       // re-mint when within this of expiry
)

// CA is a certificate authority. Key is nil when only the public ca.crt is
// present (the operator may move ca.key off-machine).
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// MintCA creates a fresh CA certificate and signing key.
func MintCA(now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "DockWatch CA"},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true, // may sign leaves only, never another CA
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LoadCACert parses a CA certificate from PEM bytes.
func LoadCACert(pemBytes []byte) (*x509.Certificate, error) {
	cert, err := firstCert(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("load ca.crt: %w", err)
	}
	return cert, nil
}

// LoadCAKey parses a CA private key from PEM bytes.
func LoadCAKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	key, err := parseKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("load ca.key: %w", err)
	}
	return key, nil
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit random serial
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return n, nil
}

func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func keyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func firstCert(pemBytes []byte) (*x509.Certificate, error) {
	certs, err := parseCerts(pemBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate in PEM")
	}
	return certs[0], nil
}

// parseCerts returns every CERTIFICATE block in order, skipping other blocks.
func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseKey returns the first ECDSA private key block (PKCS#8 or SEC1).
func parseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS8 key: %w", err)
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is %T, want ECDSA", k)
			}
			return ec, nil
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse EC key: %w", err)
			}
			return k, nil
		}
	}
	return nil, fmt.Errorf("no private key in PEM")
}
