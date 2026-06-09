package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

const agentPollTimeout = 10 * time.Second

// Agent identifies one agent to poll; its own type keeps hub independent of config.
type Agent struct {
	Name string
	URL  string
}

// localReader is a seam: *inventory.Reader in production, a fake in tests.
type localReader interface {
	Read(ctx context.Context) (inventory.Inventory, error)
}

var _ localReader = (*inventory.Reader)(nil)

// Poller gathers the local and agent inventories; a slow or failed agent is dropped, never blocking the cycle.
type Poller struct {
	local       localReader
	agents      []Agent
	client      *http.Client
	store       *store.Store
	logger      *slog.Logger
	pollTimeout time.Duration
}

// NewPoller builds a Poller; client may be nil only when agents is empty (local-only hub).
func NewPoller(local localReader, agents []Agent, client *http.Client, st *store.Store, logger *slog.Logger) *Poller {
	return &Poller{
		local:       local,
		agents:      agents,
		client:      client,
		store:       st,
		logger:      logger,
		pollTimeout: agentPollTimeout,
	}
}

// NewClient builds the hub's mTLS dialer; the TLS 1.3 floor matches the agent.
func NewClient(cert tls.Certificate, pool *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
}

// Gather reads the local socket and every agent in parallel; now stamps agent poll status.
func (p *Poller) Gather(ctx context.Context, now time.Time) []inventory.Inventory {
	type slot struct {
		inv     inventory.Inventory
		include bool
	}
	slots := make([]slot, 1+len(p.agents))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		inv, err := p.local.Read(ctx)
		if err != nil {
			p.logger.Warn("local docker read degraded", "err", err)
		}
		slots[0] = slot{inv: inv, include: true}
	}()

	for i, a := range p.agents {
		wg.Add(1)
		go func(i int, a Agent) {
			defer wg.Done()
			actx, cancel := context.WithTimeout(ctx, p.pollTimeout)
			defer cancel()
			inv, err := p.fetchAgent(actx, a)
			if err != nil {
				p.logger.Warn("agent poll failed", "agent", a.Name, "err", err)
				p.recordAgent(a.Name, false, now)
				return
			}
			inv.Host = a.Name // hub owns the display name, not the agent's hostname
			if inv.V != inventory.WireVersion {
				p.logger.Warn("agent wire version mismatch", "agent", a.Name, "agent_v", inv.V, "hub_v", inventory.WireVersion)
			}
			p.recordAgent(a.Name, true, now)
			slots[1+i] = slot{inv: inv, include: true}
		}(i, a)
	}
	wg.Wait()

	out := make([]inventory.Inventory, 0, len(slots))
	for _, s := range slots {
		if s.include {
			out = append(out, s.inv)
		}
	}
	return out
}

func (p *Poller) fetchAgent(ctx context.Context, a Agent) (inventory.Inventory, error) {
	u := strings.TrimRight(a.URL, "/") + "/v1/inventory"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return inventory.Inventory{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return inventory.Inventory{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	var inv inventory.Inventory
	if err := json.NewDecoder(resp.Body).Decode(&inv); err != nil {
		return inventory.Inventory{}, fmt.Errorf("decode inventory: %w", err)
	}
	return inv, nil
}

// recordAgent updates poll status; DownNotified is the notifier's gate, left untouched.
func (p *Poller) recordAgent(name string, ok bool, now time.Time) {
	st, _, err := p.store.GetAgent(name)
	if err != nil {
		p.logger.Warn("read agent status", "agent", name, "err", err)
	}
	st.Name = name
	st.LastPoll = now
	st.LastOK = ok
	if ok {
		st.ConsecutiveFailures = 0
	} else {
		st.ConsecutiveFailures++
	}
	if err := p.store.PutAgent(st); err != nil {
		p.logger.Warn("persist agent status", "agent", name, "err", err)
	}
}
