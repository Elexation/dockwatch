package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

const (
	// downThreshold is the consecutive failed polls before an agent-down alert.
	downThreshold = 3
	// renewalReminderEvery is the cadence of the "bundle staged but not installed" reminder.
	renewalReminderEvery = 7 * 24 * time.Hour
	// maxHostsShown caps the host list in an update message before "+N more".
	maxHostsShown = 3
)

// UpdateInput is one image reference's update facts, joined from the registry
// check result and the running inventory.
type UpdateInput struct {
	Ref            string
	Current        string   // running tag, e.g. "1.24.3" or "latest"
	Latest         string   // newest tag matching the dw.tags filter, or the scheme heuristic when unset; "" if none
	UpdateKind     string   // major | minor | patch, when computable
	RegistryDigest string   // registry index digest of the current tag
	StaleHosts     []string // hosts whose running index digest differs from RegistryDigest
	Hosts          []string // hosts running this reference
}

// Notifier turns detection and lifecycle facts into ntfy messages, persisting
// in the store what the operator has already been told so a fact is announced
// once. The one deliberate exception is the weekly reminder that a renewed
// bundle is staged but not installed, which repeats until the condition clears.
type Notifier struct {
	client *Client
	store  *store.Store
	logger *slog.Logger
	domain string // bare host for the dashboard click-through; "" omits the link

	// stagedExpiry returns the NotAfter of the agent's on-disk bundle, with
	// ok=false when none is staged or it is unreadable. Injected so this package
	// stays independent of the certificate code. May be nil (no cert reminders).
	stagedExpiry func(agent string) (time.Time, bool)

	// noDownAlert names agents whose host is not always on, so being
	// unreachable is routine and not worth a push. May be nil.
	noDownAlert map[string]bool
}

// NewNotifier builds a Notifier. domain is the bare hostname used to build a
// click-through link; stagedExpiry may be nil to disable the cert reminder;
// noDownAlert names agents that never get the unreachable alert.
func NewNotifier(client *Client, st *store.Store, logger *slog.Logger, domain string, stagedExpiry func(agent string) (time.Time, bool), noDownAlert map[string]bool) *Notifier {
	return &Notifier{
		client:       client,
		store:        st,
		logger:       logger,
		domain:       domain,
		stagedExpiry: stagedExpiry,
		noDownAlert:  noDownAlert,
	}
}

// NotifyUpdates evaluates each reference for two independent, once-each signals:
// a newer matching tag, and a republish of the current tag (its registry index
// digest moving past the last one notified while at least one host still runs
// an older digest). A signal advances the stored state only after its message
// is delivered, so a delivery failure simply retries on the next cycle.
func (n *Notifier) NotifyUpdates(ctx context.Context, inputs []UpdateInput, now time.Time) {
	if !n.client.Enabled() {
		return
	}
	for _, in := range inputs {
		prev, _, err := n.store.GetNotified(in.Ref)
		if err != nil {
			n.logger.Warn("read notified state", "ref", in.Ref, "err", err)
			continue
		}
		state := prev
		state.Ref = in.Ref
		changed := false

		if in.Latest != "" && in.Latest != prev.Version {
			if n.publish(ctx, n.updateMessage(in)) {
				state.Version = in.Latest
				state.NotifiedAt = now
				changed = true
			}
		}
		if in.RegistryDigest != "" && len(in.StaleHosts) > 0 && in.RegistryDigest != prev.Digest {
			if n.publish(ctx, n.republishMessage(in)) {
				state.Digest = in.RegistryDigest
				state.NotifiedAt = now
				changed = true
			}
		}

		if changed {
			if err := n.store.PutNotified(state); err != nil {
				n.logger.Warn("persist notified state", "ref", in.Ref, "err", err)
			}
		}
	}
}

// NotifyAgents runs the per-agent lifecycle pass over stored poll status: a
// down alert after repeated failures (unless disabled for that agent), a
// recovery on the first good poll after a down alert was sent, a
// once-per-version wire-version mismatch, and a weekly reminder while a
// renewed bundle is staged but not yet installed. It is meant to run after a
// poll cycle, never concurrently with the pollers that write the same status.
func (n *Notifier) NotifyAgents(ctx context.Context, now time.Time) {
	if !n.client.Enabled() {
		return
	}
	agents, err := n.store.AllAgents()
	if err != nil {
		n.logger.Warn("read agent statuses", "err", err)
		return
	}
	for _, a := range agents {
		n.agentTransitions(ctx, a, now)
	}
}

func (n *Notifier) agentTransitions(ctx context.Context, a store.AgentStatus, now time.Time) {
	changed := false

	switch {
	case !a.LastOK && a.ConsecutiveFailures >= downThreshold && !a.DownNotified && !n.noDownAlert[a.Name]:
		if n.publish(ctx, agentDownMessage(a.Name)) {
			a.DownNotified = true
			changed = true
		}
	case a.LastOK && a.DownNotified:
		if n.publish(ctx, agentRecoveredMessage(a.Name)) {
			a.DownNotified = false
			changed = true
		}
	}

	if a.LastOK && a.LastWireV != 0 && a.LastWireV != inventory.WireVersion && a.WireNotifiedV != a.LastWireV {
		if n.publish(ctx, wireMismatchMessage(a.Name, a.LastWireV)) {
			a.WireNotifiedV = a.LastWireV
			changed = true
		}
	}

	if a.LastOK && n.stagedExpiry != nil {
		staged, ok := n.stagedExpiry(a.Name)
		pending := ok && !a.CertNotAfter.IsZero() && a.CertNotAfter.Before(staged)
		switch {
		case pending:
			if a.LastRenewalReminder.IsZero() || now.Sub(a.LastRenewalReminder) >= renewalReminderEvery {
				if n.publish(ctx, certReminderMessage(a.Name)) {
					a.LastRenewalReminder = now
					changed = true
				}
			}
		case !a.LastRenewalReminder.IsZero():
			// Agent now serves the staged cert: clear the gate, or the reminder
			// timestamp keeps the agents-page warn flag lit forever.
			a.LastRenewalReminder = time.Time{}
			changed = true
		}
	}

	if changed {
		if err := n.store.PutAgent(a); err != nil {
			n.logger.Warn("persist agent status", "agent", a.Name, "err", err)
		}
	}
}

// NotifyBundleRenewed alerts that a renewed certificate bundle is ready to copy
// to the named agent.
func (n *Notifier) NotifyBundleRenewed(ctx context.Context, agent string) {
	n.publish(ctx, Message{
		Title: "Certificate renewed for agent " + agent,
		Body:  fmt.Sprintf("A renewed certificate bundle for agent %q is ready. Copy it to the agent and restart it.", agent),
		Tags:  []string{"lock"},
	})
}

// NotifyBundleRemintedSAN alerts that the named agent's address changed, so its
// certificate was re-issued and the new bundle must be copied over.
func (n *Notifier) NotifyBundleRemintedSAN(ctx context.Context, agent string) {
	n.publish(ctx, Message{
		Title: "Certificate re-issued for agent " + agent,
		Body:  fmt.Sprintf("Agent %q's address changed, so its certificate was re-issued. Copy the new bundle to the agent and restart it.", agent),
		Tags:  []string{"lock"},
	})
}

// NotifyCAKeyMissing alerts that minting is blocked because the CA key is
// absent; details name everything that could not be completed. It reports
// whether the message was delivered, so the caller can gate it to once per
// occurrence of the condition rather than once per renewal pass.
func (n *Notifier) NotifyCAKeyMissing(ctx context.Context, details []string) bool {
	return n.publish(ctx, Message{
		Title:    "CA key required",
		Body:     "DockWatch needs the CA key to mint certificates but it is absent: " + strings.Join(details, "; ") + ". Restore ca.key.",
		Priority: PriorityHigh,
		Tags:     []string{"rotating_light"},
	})
}

// publish sends m, filling in the click-through link, and reports whether
// delivery succeeded. A failure is logged, not returned, so callers gate their
// once-only state on the result and retry next cycle.
func (n *Notifier) publish(ctx context.Context, m Message) bool {
	if m.Click == "" {
		m.Click = n.clickURL()
	}
	if err := n.client.Publish(ctx, m); err != nil {
		n.logger.Warn("ntfy publish failed", "title", m.Title, "err", err)
		return false
	}
	return true
}

func (n *Notifier) clickURL() string {
	if n.domain == "" {
		return ""
	}
	return "https://" + n.domain + "/"
}

func (n *Notifier) updateMessage(in UpdateInput) Message {
	name := imageName(in.Ref)
	kind := ""
	if in.UpdateKind != "" {
		kind = " (" + in.UpdateKind + ")"
	}
	return Message{
		Title: name + " update available",
		Body:  fmt.Sprintf("%s %s → %s%s on %s", name, in.Current, in.Latest, kind, hostList(in.Hosts)),
		Tags:  []string{"arrow_up"},
	}
}

// republishMessage names only the hosts actually running an older digest; a
// host already on the new one has nothing to do and should not be listed.
func (n *Notifier) republishMessage(in UpdateInput) Message {
	name := imageName(in.Ref)
	body := fmt.Sprintf("%s republished on %s", name, hostList(in.StaleHosts))
	if in.Current != "" {
		body = fmt.Sprintf("%s %s republished on %s", name, in.Current, hostList(in.StaleHosts))
	}
	return Message{
		Title: name + " republished",
		Body:  body,
		Tags:  []string{"arrow_up"},
	}
}

func agentDownMessage(name string) Message {
	return Message{
		Title:    "Agent " + name + " unreachable",
		Body:     fmt.Sprintf("DockWatch cannot reach agent %q after repeated polls.", name),
		Priority: PriorityHigh,
		Tags:     []string{"warning"},
	}
}

func agentRecoveredMessage(name string) Message {
	return Message{
		Title: "Agent " + name + " recovered",
		Body:  fmt.Sprintf("Agent %q is reachable again.", name),
		Tags:  []string{"white_check_mark"},
	}
}

func wireMismatchMessage(name string, agentV int) Message {
	return Message{
		Title: "Agent " + name + " version mismatch",
		Body:  fmt.Sprintf("Agent %q reports wire version %d but the hub expects %d; update the agent or hub.", name, agentV, inventory.WireVersion),
		Tags:  []string{"warning"},
	}
}

func certReminderMessage(name string) Message {
	return Message{
		Title: "Agent " + name + " bundle not installed",
		Body:  fmt.Sprintf("A renewed certificate bundle for agent %q is staged but not yet installed. Copy it to the agent and restart it.", name),
		Tags:  []string{"lock"},
	}
}

// hostList renders hosts sorted and comma-joined, collapsing the tail past
// maxHostsShown into "+N more" so a large fleet does not produce a wall of text.
func hostList(hosts []string) string {
	h := append([]string(nil), hosts...)
	sort.Strings(h)
	if len(h) <= maxHostsShown {
		return strings.Join(h, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(h[:maxHostsShown], ", "), len(h)-maxHostsShown)
}

// imageName extracts the short display name from a reference: the last path
// segment of the repository, with any registry, tag, or digest stripped
// (gitea/gitea:1.24.3 → gitea, ghcr.io/foo/bar:tag → bar, redis:7 → redis).
func imageName(ref string) string {
	s := ref
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	last := s[strings.LastIndexByte(s, '/')+1:] // whole string when there is no '/'
	if i := strings.IndexByte(last, ':'); i >= 0 {
		last = last[:i]
	}
	return last
}
