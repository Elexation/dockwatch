package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/pki"
	"github.com/elexation/dockwatch/internal/store"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// emptyLocal is a localReader yielding a usable, container-free inventory.
type emptyLocal struct{}

func (emptyLocal) Read(context.Context) (inventory.Inventory, error) {
	return inventory.Inventory{V: inventory.WireVersion, Host: "local", Docker: inventory.DockerOK, Containers: []inventory.Container{}}, nil
}

// mtlsAgent starts an mTLS test server + a hub client that trusts it; SAN is 127.0.0.1 so the loopback URL verifies.
func mtlsAgent(t *testing.T, handler http.Handler) (url string, client *http.Client) {
	t.Helper()
	now := time.Now()
	ca, err := pki.MintCA(now)
	if err != nil {
		t.Fatal(err)
	}
	hubLeaf, err := ca.MintHubClient(now)
	if err != nil {
		t.Fatal(err)
	}
	agentLeaf, err := ca.MintAgentServer(now, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{agentLeaf.Cert.Raw}, PrivateKey: agentLeaf.Key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	hubCert := tls.Certificate{Certificate: [][]byte{hubLeaf.Cert.Raw}, PrivateKey: hubLeaf.Key}
	return ts.URL, NewClient(hubCert, pool)
}

func inventoryHandler(inv inventory.Inventory) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/inventory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inv)
	})
	return mux
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestGatherAgentOverridesHost(t *testing.T) {
	agentInv := inventory.Inventory{
		V:      inventory.WireVersion,
		Host:   "raspberrypi", // the agent's own hostname; the hub must override it
		Docker: inventory.DockerOK,
		Containers: []inventory.Container{
			{Name: "gitea", Image: "gitea/gitea:1.24.3", State: "running"},
		},
	}
	url, client := mtlsAgent(t, inventoryHandler(agentInv))
	st := openStore(t)

	now := time.Now()
	p := NewPoller(emptyLocal{}, []Agent{{Name: "home", URL: url}}, client, st, quietLogger())
	invs := p.Gather(context.Background(), now)

	if len(invs) != 2 {
		t.Fatalf("got %d inventories, want 2 (local + agent)", len(invs))
	}
	var agent inventory.Inventory
	for _, inv := range invs {
		if len(inv.Containers) == 1 {
			agent = inv
		}
	}
	if agent.Host != "home" {
		t.Errorf("agent host = %q, want hub-controlled name %q", agent.Host, "home")
	}

	status, found, err := st.GetAgent("home")
	if err != nil || !found {
		t.Fatalf("GetAgent: found=%v err=%v", found, err)
	}
	if !status.LastOK || status.ConsecutiveFailures != 0 {
		t.Errorf("status = %+v, want LastOK and 0 failures", status)
	}
}

func TestGatherAgentDownIncrementsFailures(t *testing.T) {
	st := openStore(t)

	// Nothing listens on port 1: the dial is refused.
	p := NewPoller(emptyLocal{}, []Agent{{Name: "home", URL: "https://127.0.0.1:1"}},
		NewClient(tls.Certificate{}, x509.NewCertPool()), st, quietLogger())
	p.pollTimeout = time.Second

	now := time.Now()
	invs := p.Gather(context.Background(), now)
	if len(invs) != 1 {
		t.Fatalf("got %d inventories, want 1 (local only; agent down)", len(invs))
	}
	status, found, err := st.GetAgent("home")
	if err != nil || !found {
		t.Fatalf("GetAgent: found=%v err=%v", found, err)
	}
	if status.LastOK || status.ConsecutiveFailures != 1 {
		t.Errorf("status = %+v, want !LastOK and 1 failure", status)
	}

	p.Gather(context.Background(), now)
	status, _, _ = st.GetAgent("home")
	if status.ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures = %d, want 2", status.ConsecutiveFailures)
	}
}

func TestGatherAgentRecoveryResetsFailures(t *testing.T) {
	url, client := mtlsAgent(t, inventoryHandler(inventory.Inventory{V: inventory.WireVersion, Docker: inventory.DockerOK}))
	st := openStore(t)
	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: false, ConsecutiveFailures: 5, DownNotified: true}); err != nil {
		t.Fatal(err)
	}

	p := NewPoller(emptyLocal{}, []Agent{{Name: "home", URL: url}}, client, st, quietLogger())
	p.Gather(context.Background(), time.Now())

	status, _, _ := st.GetAgent("home")
	if !status.LastOK || status.ConsecutiveFailures != 0 {
		t.Errorf("status = %+v, want LastOK and 0 failures after recovery", status)
	}
	if !status.DownNotified {
		t.Error("DownNotified must be carried through (the notifier owns its reset)")
	}
}

func TestGatherAgentTimeout(t *testing.T) {
	release := make(chan struct{})
	hang := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release })
	url, client := mtlsAgent(t, hang)
	t.Cleanup(func() { close(release) }) // runs before the server Close registered in mtlsAgent

	st := openStore(t)
	p := NewPoller(emptyLocal{}, []Agent{{Name: "home", URL: url}}, client, st, quietLogger())
	p.pollTimeout = 200 * time.Millisecond

	start := time.Now()
	invs := p.Gather(context.Background(), time.Now())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Gather took %v; per-agent timeout did not fire", elapsed)
	}
	if len(invs) != 1 {
		t.Fatalf("got %d inventories, want 1 (agent timed out)", len(invs))
	}
	if status, _, _ := st.GetAgent("home"); status.LastOK {
		t.Error("want LastOK=false after timeout")
	}
}
