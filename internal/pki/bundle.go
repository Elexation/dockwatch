package pki

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// Bundle is the parsed agent bundle.pem: the agent's own server identity plus
// the CA pool it uses to verify the hub's client cert. The agent never stores
// or pins the hub's leaf, only the CA chain.
type Bundle struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CAs     []*x509.Certificate
	TLSCert tls.Certificate // the agent's server certificate, ready for tls.Config
}

// WriteBundle concatenates the leaf cert, leaf key, and CA cert(s) into the PEM
// bytes the operator copies to the agent. Order is leaf cert, key, then CA(s);
// the CA list carries 1 normally and 2 during a CA rollover.
func WriteBundle(leaf *Leaf, cas ...*x509.Certificate) ([]byte, error) {
	if len(cas) == 0 {
		return nil, fmt.Errorf("bundle needs at least one CA")
	}
	keyPEM, err := keyToPEM(leaf.Key)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, certToPEM(leaf.Cert)...)
	out = append(out, keyPEM...)
	for _, ca := range cas {
		out = append(out, certToPEM(ca)...)
	}
	return out, nil
}

// ParseBundle pulls the leaf cert, key, and CA pool out of bundle PEM bytes.
// The first CERTIFICATE block is the leaf; the rest are CAs. It verifies key
// possession and that the leaf chains to a bundled CA, failing fast on a
// malformed or mismatched bundle.
func ParseBundle(pemBytes []byte) (*Bundle, error) {
	certs, err := parseCerts(pemBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) < 2 {
		return nil, fmt.Errorf("bundle needs a leaf and at least one CA cert, found %d", len(certs))
	}
	key, err := parseKey(pemBytes)
	if err != nil {
		return nil, err
	}
	leaf, cas := certs[0], certs[1:]
	if err := verifyKeyPossession(leaf, key); err != nil {
		return nil, err
	}
	// Structural coherence: the leaf must chain to a bundled CA. Checked at the
	// leaf's own NotBefore so this is a chain check, not a validity check (the
	// TLS handshake enforces validity at connection time).
	if err := verifyChain(leaf, NewCertPool(cas), x509.ExtKeyUsageServerAuth, leaf.NotBefore); err != nil {
		return nil, fmt.Errorf("bundle leaf does not chain to its CA: %w", err)
	}
	return &Bundle{
		Cert: leaf,
		Key:  key,
		CAs:  cas,
		TLSCert: tls.Certificate{
			Certificate: [][]byte{leaf.Raw},
			PrivateKey:  key,
			Leaf:        leaf,
		},
	}, nil
}

// ClientCAPool is the pool the agent sets as tls.Config.ClientCAs to verify the
// hub's client certificate.
func (b *Bundle) ClientCAPool() *x509.CertPool {
	return NewCertPool(b.CAs)
}
