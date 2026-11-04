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
	Agents     []store.AgentStatus // stored agent statuses; their warn flags become notices
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

	var groups []GroupVM
	for _, h := range orderHosts(order, in.LocalName) {
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
		Groups:     groups,
		FlatRows:   rows,
		DockerDown: dockerDown,
	}
	for _, a := range in.Agents {
		for _, f := range agentFlags(a) {
			vm.AgentNotices = append(vm.AgentNotices, AgentNoticeVM{Agent: a.Name, Text: f})
		}
	}
	if len(rows) == 0 {
		vm.Empty = true
		vm.Headline = "No containers found"
		vm.EmptyMsg = "Nothing is running yet on the configured hosts."
		if len(dockerDown) > 0 {
			vm.EmptyMsg = "No containers could be listed while Docker is unavailable."
		}
		return vm
	}
	counts := make(map[DisplayState]int)
	for _, r := range rows {
		counts[r.rank]++
	}
	vm.Headline, vm.HeadlineTone = headline(counts)
	vm.Fleet = fmt.Sprintf("%d %s on %d %s",
		len(rows), plural(len(rows), "container", "containers"),
		len(groups), plural(len(groups), "host", "hosts"))
	for _, t := range tallyStates {
		if n := counts[t.state]; n > 0 {
			vm.Tally = append(vm.Tally, fmt.Sprintf("%d %s", n, plural(n, t.one, t.many)))
		}
	}
	return vm
}

// headline names the dashboard's findings, newer tags before republished images.
// With neither, it claims everything is current only if no check failed or is
// still pending, since those prove nothing about the image.
func headline(n map[DisplayState]int) (text, tone string) {
	up, rep := n[StateUpdate], n[StateRepublished]
	switch {
	case up > 0 && rep > 0:
		return fmt.Sprintf("%d %s, %d republished", up, plural(up, "update", "updates"), rep), "upd"
	case up > 0:
		return fmt.Sprintf("%d %s available", up, plural(up, "update", "updates")), "upd"
	case rep > 0:
		return fmt.Sprintf("%d republished %s", rep, plural(rep, "image", "images")), "repub"
	case n[StateRate]+n[StateError]+n[StatePending] > 0:
		return "No updates found", ""
	}
	return "Everything checkable is up to date", ""
}

// tallyStates are the states the summary line counts, in display order; the
// headline already names updates and republished images.
var tallyStates = []struct {
	state     DisplayState
	one, many string
}{
	{StateCurrent, "up to date", "up to date"},
	{StateLocal, "local, not checkable", "local, not checkable"},
	{StateAuth, "auth required", "auth required"},
	{StateRate, "check delayed", "checks delayed"},
	{StateError, "check failed", "checks failed"},
	{StatePending, "not checked yet", "not checked yet"},
}

// BuildAgentCards maps stored agent statuses into the Settings agent cards;
// reachability resolves unreachable over Docker-unavailable over reachable.
// docker maps agent names to the Docker status of the last inventory that got
// through, so it says nothing about an agent that is down now.
func BuildAgentCards(agents []store.AgentStatus, docker map[string]string) []AgentCardVM {
	var cards []AgentCardVM
	for _, a := range agents {
		card := AgentCardVM{
			Name:         a.Name,
			LastSuccess:  a.LastSuccess,
			CertNotAfter: a.CertNotAfter,
			Flags:        agentFlags(a),
		}
		switch {
		case !a.LastOK:
			card.ReachClass, card.ReachLabel = "down", "unreachable"
		case docker[a.Name] == inventory.DockerUnavailable:
			card.ReachClass, card.ReachLabel = "nodocker", "Docker unavailable"
		default:
			card.ReachClass, card.ReachLabel = "ok", "reachable"
		}
		cards = append(cards, card)
	}
	return cards
}

// agentFlags returns the warn-flag texts for one agent; nil if none apply.
func agentFlags(a store.AgentStatus) []string {
	var flags []string
	switch {
	case a.LastWireV > inventory.WireVersion:
		flags = append(flags,
			fmt.Sprintf("Update hub: agent is newer (agent v%d, hub v%d).", a.LastWireV, inventory.WireVersion))
	case a.LastWireV != 0 && a.LastWireV < inventory.WireVersion:
		flags = append(flags,
			fmt.Sprintf("Update agent: agent is older (agent v%d, hub v%d).", a.LastWireV, inventory.WireVersion))
	}
	if !a.LastRenewalReminder.IsZero() {
		flags = append(flags,
			"Renewed bundle not yet installed. Agent still serving the previous certificate.")
	}
	return flags
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
