package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testNow = time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

func hasExtUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, u := range cert.ExtKeyUsage {
		if u == want {
			return true
		}
	}
	return false
}

func approx(t *testing.T, label string, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d < -time.Second || d > time.Second {
		t.Errorf("%s = %v, want ~%v (off by %v)", label, got, want, d)
	}
}

func TestMintCA(t *testing.T) {
	ca, err := MintCA(testNow)
	if err != nil {
		t.Fatalf("MintCA: %v", err)
	}
	c := ca.Cert
	if !c.IsCA {
		t.Error("CA cert IsCA = false")
	}
	if !c.MaxPathLenZero {
		t.Error("CA MaxPathLenZero = false, want true (may sign leaves only)")
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA missing KeyUsageCertSign")
	}
	if c.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("CA key algorithm = %v, want ECDSA", c.PublicKeyAlgorithm)
	}
	approx(t, "CA NotBefore", c.NotBefore, testNow.Add(-backdate))
	approx(t, "CA NotAfter", c.NotAfter, testNow.Add(caValidity))
}

func TestMintHubClient(t *testing.T) {
	ca, _ := MintCA(testNow)
	leaf, err := ca.MintHubClient(testNow)
	if err != nil {
		t.Fatalf("MintHubClient: %v", err)
	}
	if leaf.Cert.IsCA {
		t.Error("hub leaf IsCA = true")
	}
	if !hasExtUsage(leaf.Cert, x509.ExtKeyUsageClientAuth) {
		t.Error("hub leaf missing ClientAuth")
	}
	if hasExtUsage(leaf.Cert, x509.ExtKeyUsageServerAuth) {
		t.Error("hub leaf must not have ServerAuth")
	}
	approx(t, "leaf NotBefore", leaf.Cert.NotBefore, testNow.Add(-backdate))
	approx(t, "leaf NotAfter", leaf.Cert.NotAfter, testNow.Add(leafValidity))
}

func TestMintAgentServerSAN(t *testing.T) {
	ca, _ := MintCA(testNow)

	ipLeaf, err := ca.MintAgentServer(testNow, "10.27.27.8")
	if err != nil {
		t.Fatalf("MintAgentServer(ip): %v", err)
	}
	if !hasExtUsage(ipLeaf.Cert, x509.ExtKeyUsageServerAuth) {
		t.Error("agent leaf missing ServerAuth")
	}
	if !sanMatches(ipLeaf.Cert, "10.27.27.8") {
		t.Errorf("IP SAN not set: IPs=%v", ipLeaf.Cert.IPAddresses)
	}
	if len(ipLeaf.Cert.DNSNames) != 0 {
		t.Errorf("IP host should not set DNSNames, got %v", ipLeaf.Cert.DNSNames)
	}

	dnsLeaf, err := ca.MintAgentServer(testNow, "agent.lan")
	if err != nil {
		t.Fatalf("MintAgentServer(dns): %v", err)
	}
	if !sanMatches(dnsLeaf.Cert, "agent.lan") {
		t.Errorf("DNS SAN not set: DNS=%v", dnsLeaf.Cert.DNSNames)
	}
	if len(dnsLeaf.Cert.IPAddresses) != 0 {
		t.Errorf("DNS host should not set IPAddresses, got %v", dnsLeaf.Cert.IPAddresses)
	}
}

func TestMintLeafRequiresCAKey(t *testing.T) {
	ca, _ := MintCA(testNow)
	ca.Key = nil // simulate ca.key moved off-machine
	if _, err := ca.MintHubClient(testNow); err == nil {
		t.Error("expected error minting without ca.key")
	}
}

func TestBundleRoundTrip(t *testing.T) {
	ca, _ := MintCA(testNow)
	leaf, _ := ca.MintAgentServer(testNow, "agent.lan")

	pemBytes, err := WriteBundle(leaf, ca.Cert)
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	b, err := ParseBundle(pemBytes)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if !b.Cert.Equal(leaf.Cert) {
		t.Error("round-tripped leaf differs")
	}
	if len(b.CAs) != 1 || !b.CAs[0].Equal(ca.Cert) {
		t.Errorf("round-tripped CAs = %d, want the one CA", len(b.CAs))
	}
	if b.TLSCert.Leaf == nil || b.TLSCert.PrivateKey == nil {
		t.Error("TLSCert not populated")
	}
	if b.ClientCAPool() == nil {
		t.Error("ClientCAPool is nil")
	}
}

func TestParseBundleRejects(t *testing.T) {
	ca, _ := MintCA(testNow)
	leaf, _ := ca.MintAgentServer(testNow, "agent.lan")

	// Only a leaf, no CA.
	leafOnly := certToPEM(leaf.Cert)
	keyPEM, _ := keyToPEM(leaf.Key)
	if _, err := ParseBundle(append(leafOnly, keyPEM...)); err == nil {
		t.Error("expected error for bundle with no CA cert")
	}

	// Mismatched key (a different leaf's key).
	other, _ := ca.MintAgentServer(testNow, "agent.lan")
	otherKey, _ := keyToPEM(other.Key)
	bad := append(append(certToPEM(leaf.Cert), otherKey...), certToPEM(ca.Cert)...)
	if _, err := ParseBundle(bad); err == nil {
		t.Error("expected key-possession failure for mismatched key")
	}

	// Garbage.
	if _, err := ParseBundle([]byte("not pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestNeedsRenewal(t *testing.T) {
	ca, _ := MintCA(testNow)
	leaf, _ := ca.MintHubClient(testNow)

	if needsRenewal(leaf.Cert, testNow) {
		t.Error("fresh 10y leaf should not need renewal")
	}
	// 30 days before expiry: inside the 90-day window.
	near := leaf.Cert.NotAfter.Add(-30 * 24 * time.Hour)
	if !needsRenewal(leaf.Cert, near) {
		t.Error("leaf 30d from expiry should need renewal")
	}
}

// --- Bootstrap orchestration ---

func kinds(events []Event) []EventKind {
	out := make([]EventKind, len(events))
	for i, e := range events {
		out[i] = e.Kind
	}
	return out
}

func hasKind(events []Event, k EventKind) bool {
	for _, e := range events {
		if e.Kind == k {
			return true
		}
	}
	return false
}

func TestBootstrapMintsThenIdempotent(t *testing.T) {
	dir := t.TempDir()
	agents := []AgentRef{{Name: "home", Host: "10.0.0.5"}}

	ev, err := Bootstrap(dir, agents, testNow)
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	want := []EventKind{MintedCA, MintedHub, MintedBundle}
	if got := kinds(ev); len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("first run events = %v, want %v", got, want)
	}
	for _, f := range []string{"ca.crt", "ca.key", "hub.crt", "hub.key", filepath.Join("agents", "home", "bundle.pem")} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to exist: %v", f, err)
		}
	}

	// Second run mints nothing.
	ev2, err := Bootstrap(dir, agents, testNow)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if len(ev2) != 0 {
		t.Errorf("second run events = %v, want none", kinds(ev2))
	}
}

func TestBootstrapAddAgent(t *testing.T) {
	dir := t.TempDir()
	if _, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, testNow); err != nil {
		t.Fatalf("seed Bootstrap: %v", err)
	}
	ev, err := Bootstrap(dir, []AgentRef{
		{Name: "home", Host: "10.0.0.5"},
		{Name: "work", Host: "10.0.0.6"},
	}, testNow)
	if err != nil {
		t.Fatalf("add-agent Bootstrap: %v", err)
	}
	if got := kinds(ev); len(got) != 1 || got[0] != MintedBundle {
		t.Fatalf("add-agent events = %v, want only minted-bundle", got)
	}
	if ev[0].Name != "work" {
		t.Errorf("minted bundle for %q, want work", ev[0].Name)
	}
}

func TestBootstrapSANChange(t *testing.T) {
	dir := t.TempDir()
	if _, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, testNow); err != nil {
		t.Fatalf("seed Bootstrap: %v", err)
	}
	ev, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.9"}}, testNow)
	if err != nil {
		t.Fatalf("SAN-change Bootstrap: %v", err)
	}
	if !hasKind(ev, RemintedSAN) {
		t.Fatalf("events = %v, want reminted-san", kinds(ev))
	}
	// The new bundle's leaf must carry the new SAN.
	b, err := os.ReadFile(filepath.Join(dir, "agents", "home", "bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := firstCert(b)
	if !sanMatches(leaf, "10.0.0.9") {
		t.Error("re-minted bundle does not carry the new host SAN")
	}
}

func TestBootstrapCAKeyMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, testNow); err != nil {
		t.Fatalf("seed Bootstrap: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	ev, err := Bootstrap(dir, []AgentRef{
		{Name: "home", Host: "10.0.0.5"},
		{Name: "work", Host: "10.0.0.6"},
	}, testNow)
	if err != nil {
		t.Fatalf("ca.key-missing Bootstrap: %v", err)
	}
	if !hasKind(ev, CAKeyMissing) {
		t.Fatalf("events = %v, want ca-key-missing", kinds(ev))
	}
	if _, err := os.Stat(filepath.Join(dir, "agents", "work", "bundle.pem")); err == nil {
		t.Error("work bundle should not be minted without ca.key")
	}
}

func TestBootstrapOrphan(t *testing.T) {
	dir := t.TempDir()
	if _, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, testNow); err != nil {
		t.Fatalf("seed Bootstrap: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "agents", "ghost"), 0o700); err != nil {
		t.Fatal(err)
	}
	ev, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, testNow)
	if err != nil {
		t.Fatalf("orphan Bootstrap: %v", err)
	}
	if !hasKind(ev, OrphanedAgent) {
		t.Fatalf("events = %v, want orphaned-agent", kinds(ev))
	}
}

func TestBootstrapRenewal(t *testing.T) {
	dir := t.TempDir()
	if _, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, testNow); err != nil {
		t.Fatalf("seed Bootstrap: %v", err)
	}
	// Jump to within the 90-day window of the 10-year leaves.
	later := testNow.Add(leafValidity - 30*24*time.Hour)
	ev, err := Bootstrap(dir, []AgentRef{{Name: "home", Host: "10.0.0.5"}}, later)
	if err != nil {
		t.Fatalf("renewal Bootstrap: %v", err)
	}
	if !hasKind(ev, Renewed) {
		t.Fatalf("events = %v, want renewed", kinds(ev))
	}
}
