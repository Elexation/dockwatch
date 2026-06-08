package pki

import (
	"crypto/x509"
	"time"
)

// needsRenewal reports whether cert is within renewWindow of expiring.
func needsRenewal(cert *x509.Certificate, now time.Time) bool {
	return now.Add(renewWindow).After(cert.NotAfter)
}
