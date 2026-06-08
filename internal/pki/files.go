package pki

import (
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
	Renewed       EventKind = "renewed"
	CAKeyMissing  EventKind = "ca-key-missing"
	OrphanedAgent EventKind = "orphaned-agent"
)

// Event is one notable thing Bootstrap did or noticed. Events feed logging now
// and notifications (ntfy) later.
type Event struct {
	Kind EventKind
	Name string // agent name, when relevant
	Msg  string
}

// Bootstrap applies the startup minting and renewal rules against dir: mint
// whatever is missing, reuse whatever exists, re-mint on SAN drift or imminent
// expiry. It never deletes anything. The returned events are for
// logging/notification; a non-nil error is fatal and means the certs dir is
// unreadable or corrupt (fail-fast).
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
	certPEM, err := os.ReadFile(certPath)
	switch {
	case err == nil:
		// CA cert exists; load it, plus the key if present (it may be off-machine).
		cert, lerr := LoadCACert(certPEM)
		if lerr != nil {
			return nil, lerr
		}
		ca := &CA{Cert: cert}
		if keyPEM, kerr := os.ReadFile(filepath.Join(dir, caKeyFile)); kerr == nil {
			key, perr := LoadCAKey(keyPEM)
			if perr != nil {
				return nil, perr
			}
			ca.Key = key
		}
		return ca, nil
	case errors.Is(err, os.ErrNotExist):
		// First boot: mint the CA (writes both ca.crt and ca.key).
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
		if !needsRenewal(cert, now) {
			return nil
		}
		return mintHub(dir, ca, now, events, Renewed, "renewed hub client cert", "hub cert renewal")
	case errors.Is(err, os.ErrNotExist):
		return mintHub(dir, ca, now, events, MintedHub, "minted hub client cert", "hub cert minting")
	default:
		return fmt.Errorf("read %s: %w", certPath, err)
	}
}

func mintHub(dir string, ca *CA, now time.Time, events *[]Event, kind EventKind, msg, need string) error {
	if ca.Key == nil {
		*events = append(*events, caKeyMissingEvent(need))
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
		*events = append(*events, caKeyMissingEvent(fmt.Sprintf("bundle for agent %q", a.Name)))
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

func caKeyMissingEvent(what string) Event {
	return Event{Kind: CAKeyMissing, Msg: fmt.Sprintf("ca.key absent: cannot complete %s; restore ca.key", what)}
}

func writeCA(dir string, ca *CA) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}
	if err := writeFile(filepath.Join(dir, caCertFile), certToPEM(ca.Cert), pubPerm); err != nil {
		return err
	}
	keyPEM, err := keyToPEM(ca.Key)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, caKeyFile), keyPEM, privPerm)
}

func writeHub(dir string, leaf *Leaf) error {
	if err := writeFile(filepath.Join(dir, hubCertFile), certToPEM(leaf.Cert), pubPerm); err != nil {
		return err
	}
	keyPEM, err := keyToPEM(leaf.Key)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, hubKeyFile), keyPEM, privPerm)
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile applies perm only when creating; enforce it for overwrites too.
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
