package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// File and directory layout under the certs dir.
const (
	caCertFile  = "ca.crt"
	caKeyFile   = "ca.key"
	hubCertFile = "hub.crt"
	hubKeyFile  = "hub.key"
	agentsDir   = "agents"
	bundleFile  = "bundle.pem"
)

const (
	pubPerm  os.FileMode = 0o644 // public certs
	privPerm os.FileMode = 0o600 // keys and bundles
	dirPerm  os.FileMode = 0o700
)

// AgentRef is one configured agent the hub must hold a bundle for. Host is the
// SAN (IP or DNS) taken from DW_AGENT_<NAME>_URL; Name is its canonical name.
type AgentRef struct {
	Name string
	Host string
}

// EventKind classifies a Bootstrap outcome.
type EventKind string

const (
	MintedCA      EventKind = "minted-ca"
	MintedHub     EventKind = "minted-hub"
	MintedBundle  EventKind = "minted-bundle"
	RemintedSAN   EventKind = "reminted-san"
	RemintedCA    EventKind = "reminted-ca"
	Renewed       EventKind = "renewed"
	CAKeyMissing  EventKind = "ca-key-missing"
	OrphanedAgent EventKind = "orphaned-agent"
)

// Event is one notable thing Bootstrap did or noticed. Every event is logged;
// the caller also notifies an agent bundle that was renewed or re-minted (new
// address or new CA) and a missing CA key, and leaves the rest log-only.
type Event struct {
	Kind   EventKind
	Name   string // agent name, when relevant
	Detail string // structured detail for notification rendering (CA-key-missing)
	Msg    string
}

// Bootstrap applies the startup minting and renewal rules against dir: mint
// whatever is missing, reuse whatever exists, and re-mint a leaf on SAN drift,
// imminent expiry, a signature from a previous CA, or a missing or mismatched
// hub.key. It never deletes anything, so a ca.key left without its ca.crt is an
// error rather than overwritten. The returned events are for logging and
// notification. A non-nil error means the certs dir is unreadable or
// inconsistent; it is fatal at startup, and the daily renewal pass logs it.
func Bootstrap(dir string, agents []AgentRef, now time.Time) ([]Event, error) {
	var events []Event

	ca, err := loadOrMintCA(dir, now, &events)
	if err != nil {
		return events, err
	}
	if err := ensureHubCert(dir, ca, now, &events); err != nil {
		return events, err
	}
	for _, a := range agents {
		if err := ensureBundle(dir, ca, a, now, &events); err != nil {
			return events, err
		}
	}
	if err := noteOrphans(dir, agents, &events); err != nil {
		return events, err
	}
	return events, nil
}

func loadOrMintCA(dir string, now time.Time, events *[]Event) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certPEM, err := os.ReadFile(certPath)
	switch {
	case err == nil:
		// CA cert exists; load it, plus the key if present (it may be off-machine).
		certs, lerr := parseCerts(certPEM)
		if lerr == nil && len(certs) == 0 {
			lerr = errors.New("no certificate in PEM")
		}
		if lerr != nil {
			return nil, fmt.Errorf("load ca.crt: %w", lerr)
		}
		ca := &CA{Cert: certs[0], Trusted: certs}
		keyPEM, kerr := os.ReadFile(keyPath)
		if errors.Is(kerr, os.ErrNotExist) {
			return ca, nil
		}
		if kerr != nil {
			return nil, fmt.Errorf("read %s: %w", keyPath, kerr)
		}
		key, perr := LoadCAKey(keyPEM)
		if perr != nil {
			return nil, perr
		}
		// During a rollover ca.crt holds two CAs in either order; ca.key picks the signer.
		for _, c := range certs {
			if verifyKeyPossession(c, key) == nil {
				ca.Cert, ca.Key = c, key
				return ca, nil
			}
		}
		return nil, errors.New("load ca.key: private key matches no certificate in ca.crt")
	case errors.Is(err, os.ErrNotExist):
		// Minting would overwrite a surviving ca.key, the only copy of the old CA.
		if _, serr := os.Stat(keyPath); serr == nil {
			return nil, fmt.Errorf("%s exists without %s: restore %s, or delete %s to start a new CA and re-copy every agent bundle",
				caKeyFile, caCertFile, caCertFile, caKeyFile)
		} else if !errors.Is(serr, os.ErrNotExist) {
			return nil, fmt.Errorf("stat %s: %w", keyPath, serr)
		}
		// No CA yet: mint one (writes both ca.key and ca.crt).
		ca, merr := MintCA(now)
		if merr != nil {
			return nil, merr
		}
		if werr := writeCA(dir, ca); werr != nil {
			return nil, werr
		}
		*events = append(*events, Event{Kind: MintedCA, Msg: "minted new CA"})
		return ca, nil
	default:
		return nil, fmt.Errorf("read %s: %w", certPath, err)
	}
}

func ensureHubCert(dir string, ca *CA, now time.Time, events *[]Event) error {
	certPath := filepath.Join(dir, hubCertFile)
	certPEM, err := os.ReadFile(certPath)
	switch {
	case err == nil:
		cert, perr := firstCert(certPEM)
		if perr != nil {
			return fmt.Errorf("read %s: %w", certPath, perr)
		}
		if needsRenewal(cert, now) {
			return mintHub(dir, ca, now, events, Renewed, "renewed hub client cert", "hub cert renewal")
		}
		if !ca.issued(cert) {
			return mintHub(dir, ca, now, events, MintedHub, "re-minted hub client cert: hub.crt was signed by a previous CA", "hub cert minting")
		}
		ok, kerr := hubKeyMatches(dir, cert)
		if kerr != nil {
			return kerr
		}
		if !ok {
			return mintHub(dir, ca, now, events, MintedHub, "re-minted hub client cert: hub.key was missing or did not match", "hub cert minting")
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		return mintHub(dir, ca, now, events, MintedHub, "minted hub client cert", "hub cert minting")
	default:
		return fmt.Errorf("read %s: %w", certPath, err)
	}
}

func mintHub(dir string, ca *CA, now time.Time, events *[]Event, kind EventKind, msg, need string) error {
	if ca.Key == nil {
		*events = append(*events, caKeyMissingEvent(need, ""))
		return nil
	}
	leaf, err := ca.MintHubClient(now)
	if err != nil {
		return err
	}
	if err := writeHub(dir, leaf); err != nil {
		return err
	}
	*events = append(*events, Event{Kind: kind, Msg: msg})
	return nil
}

// hubKeyMatches reports whether hub.key holds cert's private key. A missing or
// unparseable key is false, so the pair is re-minted rather than left broken.
func hubKeyMatches(dir string, cert *x509.Certificate) (bool, error) {
	keyPath := filepath.Join(dir, hubKeyFile)
	keyPEM, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", keyPath, err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return false, nil
	}
	return verifyKeyPossession(cert, key) == nil, nil
}

func ensureBundle(dir string, ca *CA, a AgentRef, now time.Time, events *[]Event) error {
	bundlePath := filepath.Join(dir, agentsDir, a.Name, bundleFile)
	bundlePEM, err := os.ReadFile(bundlePath)
	switch {
	case err == nil:
		leaf, perr := firstCert(bundlePEM)
		if perr != nil {
			return fmt.Errorf("read %s: %w", bundlePath, perr)
		}
		switch {
		case !sanMatches(leaf, a.Host):
			// Agent's host changed: re-mint the bundle so its SAN still matches.
			return remintBundle(dir, ca, a, now, events, RemintedSAN,
				fmt.Sprintf("agent %q host changed to %s; re-copy bundle", a.Name, a.Host))
		case needsRenewal(leaf, now):
			return remintBundle(dir, ca, a, now, events, Renewed,
				fmt.Sprintf("renewed bundle for agent %q; re-copy to install", a.Name))
		case !ca.issued(leaf):
			// ca.crt was replaced, so this bundle can no longer verify the hub.
			return remintBundle(dir, ca, a, now, events, RemintedCA,
				fmt.Sprintf("re-minted bundle for agent %q: the old one was signed by a previous CA; re-copy to install", a.Name))
		default:
			return nil
		}
	case errors.Is(err, os.ErrNotExist):
		return remintBundle(dir, ca, a, now, events, MintedBundle,
			fmt.Sprintf("minted bundle for agent %q", a.Name))
	default:
		return fmt.Errorf("read %s: %w", bundlePath, err)
	}
}

func remintBundle(dir string, ca *CA, a AgentRef, now time.Time, events *[]Event, kind EventKind, msg string) error {
	if ca.Key == nil {
		*events = append(*events, caKeyMissingEvent(fmt.Sprintf("bundle for agent %q", a.Name), a.Name))
		return nil
	}
	leaf, err := ca.MintAgentServer(now, a.Host)
	if err != nil {
		return err
	}
	bundle, err := WriteBundle(leaf, ca.Cert)
	if err != nil {
		return err
	}
	d := filepath.Join(dir, agentsDir, a.Name)
	if err := os.MkdirAll(d, dirPerm); err != nil {
		return fmt.Errorf("create %s: %w", d, err)
	}
	if err := writeFile(filepath.Join(d, bundleFile), bundle, privPerm); err != nil {
		return err
	}
	*events = append(*events, Event{Kind: kind, Name: a.Name, Msg: msg})
	return nil
}

// noteOrphans lists agents/<name> dirs with no matching DW_AGENT_*_URL. They
// are left in place, never auto-deleted (the operator may be mid-rename).
func noteOrphans(dir string, agents []AgentRef, events *[]Event) error {
	root := filepath.Join(dir, agentsDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", root, err)
	}
	want := make(map[string]bool, len(agents))
	for _, a := range agents {
		want[a.Name] = true
	}
	for _, e := range entries {
		if e.IsDir() && !want[e.Name()] {
			*events = append(*events, Event{
				Kind: OrphanedAgent,
				Name: e.Name(),
				Msg:  fmt.Sprintf("orphaned agent dir %q (no matching DW_AGENT_*_URL); left in place", e.Name()),
			})
		}
	}
	return nil
}

func caKeyMissingEvent(detail, name string) Event {
	return Event{
		Kind:   CAKeyMissing,
		Name:   name,
		Detail: detail,
		Msg:    fmt.Sprintf("ca.key absent: cannot complete %s; restore ca.key", detail),
	}
}

// writeCA and writeHub write the key before the cert. The cert's presence and
// expiry decide whether to re-mint, so a crash between the two writes leaves a
// state the next Bootstrap repairs or names, never a cert with no usable key.
func writeCA(dir string, ca *CA) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}
	keyPEM, err := keyToPEM(ca.Key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, caKeyFile), keyPEM, privPerm); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, caCertFile), certToPEM(ca.Cert), pubPerm)
}

func writeHub(dir string, leaf *Leaf) error {
	keyPEM, err := keyToPEM(leaf.Key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, hubKeyFile), keyPEM, privPerm); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, hubCertFile), certToPEM(leaf.Cert), pubPerm)
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	// Write to a temp file in the same dir, then rename over the target so a
	// reader never sees a partial file and the final mode lands atomically with
	// the name. os.CreateTemp makes the temp 0600, so keys are never momentarily
	// world-readable on overwrite.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}
