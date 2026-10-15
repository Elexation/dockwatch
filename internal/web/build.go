package web

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

// DashboardInput carries the page-level inputs beyond the raw inventories and checks.
type DashboardInput struct {
	LocalName        string    // host name of the local hub, sorted first
	Theme            string    // "light" or "dark"; dark is the default
	Layout           string    // "grouped" or "flat"
	LastCycle        time.Time // last completed check cycle
	NotificationsOff bool      // DW_NTFY_TOPIC unset
	Checking         bool
	// StaleHosts maps every unreachable agent to its last successful poll. Its
	// containers still render, from the poller's last-known inventory, so
	// presence here is what tells a reader those rows are a past snapshot.
	StaleHosts map[string]time.Time
}

// AgentsInput carries the page-level inputs for the agents page.
type AgentsInput struct {
	Theme            string    // "light" or "dark"; dark is the default
	LastCycle        time.Time // last completed check cycle
	NotificationsOff bool      // DW_NTFY_TOPIC unset
	Checking         bool
	DockerStatus     map[string]string // agent name -> inventory.DockerOK or DockerUnavailable
}

// BuildDashboard maps inventories and checks into the dashboard model, mirroring
// the scheduler's watch gate exactly (running and dw.watch != false).
func BuildDashboard(invs []inventory.Inventory, checks []store.CheckResult, in DashboardInput) DashboardVM {
	byRef := make(map[string]store.CheckResult, len(checks))
	for _, ch := range checks {
		byRef[ch.Ref] = ch
	}

	var rows []RowVM
	var dockerDown []HostNoticeVM
	seen := map[string]bool{}
	var order []string
	for _, inv := range invs {
		lastSeen, stale := in.StaleHosts[inv.Host]
		if inv.Docker == inventory.DockerUnavailable {
			dockerDown = append(dockerDown, HostNoticeVM{Host: inv.Host, Stale: stale, LastSeen: lastSeen})
		}
		for _, c := range inv.Containers {
			if c.State != "running" || c.Labels["dw.watch"] == "false" {
				continue
			}
			ch, found := byRef[inventory.Ref(c.Image)] // the scheduler's key, not the raw spelling
			st := deriveState(c, ch, found)
			row := RowVM{
				Host:     inv.Host,
				Name:     c.Name,
				Image:    c.Image,
				State:    st.String(),
				Health:   c.Health,
				Checked:  ch.CheckedAt,
				Stale:    stale,
				LastSeen: lastSeen,
				rank:     st,
			}
			switch st {
			case StateUpdate:
				row.From, row.To, row.Bump = ch.Current, ch.Latest, ch.UpdateKind
			case StateRepublished:
				row.RepublishedAt = ch.RepublishedAt
				row.RepublishedEstimated = ch.RepublishedEstimated
			case StateError:
				row.Err = ch.Err
			}
			rows = append(rows, row)
			if inv.Host != "" && !seen[inv.Host] {
				seen[inv.Host] = true
				order = append(order, inv.Host)
			}
		}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank < rows[j].rank
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})

	hosts := orderHosts(order, in.LocalName)
	var groups []GroupVM
	updates := 0
	for _, r := range rows {
		if r.rank == StateUpdate {
			updates++
		}
	}
	for _, h := range hosts {
		var hr []RowVM
		hup := 0
		for _, r := range rows {
			if r.Host != h {
				continue
			}
			hr = append(hr, r)
			if r.rank == StateUpdate {
				hup++
			}
		}
		if len(hr) == 0 {
			continue
		}
		lastSeen, stale := in.StaleHosts[h]
		groups = append(groups, GroupVM{Host: h, Count: len(hr), Updates: hup, Stale: stale, LastSeen: lastSeen, Rows: hr})
	}

	vm := DashboardVM{
		Chrome: ChromeVM{
			Active:           "dashboard",
			Theme:            in.Theme,
			Layout:           in.Layout,
			LastCycle:        in.LastCycle,
			NotificationsOff: in.NotificationsOff,
			Checking:         in.Checking,
		},
		Hosts:      hosts,
		Groups:     groups,
		FlatRows:   rows,
		DockerDown: dockerDown,
	}
	if len(rows) == 0 {
		vm.Empty = true
		vm.EmptyMsg = "Nothing is running yet on the configured hosts."
		if len(dockerDown) > 0 {
			vm.EmptyMsg = "No containers could be listed while Docker is unavailable."
		}
		return vm
	}
	tail := fmt.Sprintf("%d %s", updates, plural(updates, "update", "updates"))
	if in.Checking {
		tail = "checking…" // matches the tail app.js swaps in mid-cycle
	}
	vm.Summary = fmt.Sprintf("%d of %d containers · %s", len(rows), len(rows), tail)
	return vm
}

// BuildAgents maps stored agent statuses into the agents page model; reachability
// resolves unreachable over Docker-unavailable over reachable. The Docker status
// comes from the last inventory that got through, so it says nothing about an
// agent that is down now.
func BuildAgents(agents []store.AgentStatus, in AgentsInput) AgentsVM {
	vm := AgentsVM{
		Chrome: ChromeVM{
			Active:           "agents",
			Theme:            in.Theme,
			LastCycle:        in.LastCycle,
			NotificationsOff: in.NotificationsOff,
			Checking:         in.Checking,
		},
		Empty: len(agents) == 0,
	}
	for _, a := range agents {
		card := AgentCardVM{
			Name:         a.Name,
			LastSuccess:  a.LastSuccess,
			CertNotAfter: a.CertNotAfter,
		}
		switch {
		case !a.LastOK:
			card.ReachClass, card.ReachLabel = "down", "unreachable"
		case in.DockerStatus[a.Name] == inventory.DockerUnavailable:
			card.ReachClass, card.ReachLabel = "nodocker", "Docker unavailable"
		default:
			card.ReachClass, card.ReachLabel = "ok", "reachable"
		}
		switch {
		case a.LastWireV > inventory.WireVersion:
			card.Flags = append(card.Flags,
				fmt.Sprintf("Update hub: agent is newer (agent v%d, hub v%d).", a.LastWireV, inventory.WireVersion))
		case a.LastWireV != 0 && a.LastWireV < inventory.WireVersion:
			card.Flags = append(card.Flags,
				fmt.Sprintf("Update agent: agent is older (agent v%d, hub v%d).", a.LastWireV, inventory.WireVersion))
		}
		if !a.LastRenewalReminder.IsZero() {
			card.Flags = append(card.Flags,
				"Renewed bundle not yet installed. Agent still serving the previous certificate.")
		}
		vm.Cards = append(vm.Cards, card)
	}
	return vm
}

// orderHosts returns the seen hosts with the local host first, the rest in first-seen order.
func orderHosts(seen []string, local string) []string {
	out := make([]string, 0, len(seen))
	for _, h := range seen {
		if h == local {
			out = append(out, h)
			break
		}
	}
	for _, h := range seen {
		if h != local {
			out = append(out, h)
		}
	}
	return out
}

// relativeTime renders t as a short "5m ago" string; a zero time yields "" for the caller's placeholder.
func relativeTime(now, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(d/(24*time.Hour)))
	}
}

// runningIndexDigest returns the index digest the container runs for ref (matching
// repo_digests entry, else first). Duplicated from internal/hub to stay off its deps.
func runningIndexDigest(c inventory.Container, ref string) string {
	want := bareRepo(ref)
	first := ""
	for _, rd := range c.RepoDigests {
		at := strings.IndexByte(rd, '@')
		if at < 0 {
			continue
		}
		repo, dig := rd[:at], rd[at+1:]
		if first == "" {
			first = dig
		}
		if bareRepo(repo) == want {
			return dig
		}
	}
	return first
}

// bareRepo reduces a reference to its bare repository path (no host, tag, digest,
// or leading library/, Docker Hub's implied namespace). Duplicated from internal/hub.
func bareRepo(s string) string {
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		if j := strings.IndexByte(s[i+1:], ':'); j >= 0 {
			s = s[:i+1+j]
		}
	} else if j := strings.IndexByte(s, ':'); j >= 0 {
		s = s[:j]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		if host := s[:i]; strings.ContainsAny(host, ".:") || host == "localhost" {
			s = s[i+1:]
		}
	}
	return strings.TrimPrefix(s, "library/")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
