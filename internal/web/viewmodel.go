package web

import (
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

// DisplayState is the resolved version-cell state for one row; the constants
// are ordered by the dashboard's default sort rank, lower sorting first.
type DisplayState int

const (
	StateUpdate      DisplayState = iota // a newer same-scheme tag exists
	StateRepublished                     // the pinned tag's registry index digest moved
	StateChecking                        // live, JS-only; the builder never emits it
	StateRate                            // registry rate-limited the check
	StateCurrent                         // up to date
	StateLocal                           // locally built image, not checkable
	StateAuth                            // registry demands auth, not checkable
	StatePending                         // never checked yet
)

// String returns the lowercase token used in templates and CSS class names.
func (s DisplayState) String() string {
	switch s {
	case StateUpdate:
		return "update"
	case StateRepublished:
		return "republished"
	case StateChecking:
		return "checking"
	case StateRate:
		return "rate"
	case StateCurrent:
		return "current"
	case StateLocal:
		return "local"
	case StateAuth:
		return "auth"
	default:
		return "pending"
	}
}

// Reachability is an agent's resolved contact state, used only while building agent cards.
type Reachability int

const (
	ReachOK       Reachability = iota // reachable, Docker up
	ReachDown                         // unreachable
	ReachNoDocker                     // reachable but the Docker daemon is down
)

// ChromeVM is the shared app-page chrome (header plus notifications notice).
type ChromeVM struct {
	Active           string // "dashboard" or "agents"; drives aria-current
	Theme            string // "auto", "light", or "dark"
	Layout           string // "grouped" or "flat"; dashboard only
	LastCycle        time.Time
	NotificationsOff bool
}

// RowVM is one container row on the dashboard.
type RowVM struct {
	Host          string
	Name          string
	Image         string
	State         string // DisplayState.String(), for the template switch
	From          string // SEMVER: running version
	To            string // SEMVER: newest available version
	Bump          string // "major", "minor", or "patch"
	RepublishedAt time.Time
	Health        string // "healthy", "unhealthy", "starting", or "" for none
	Checked       time.Time

	rank DisplayState // unexported: the sort key
}

// GroupVM is one host's card in the grouped dashboard view.
type GroupVM struct {
	Host    string
	Count   int
	Updates int // rows in StateUpdate, for the accent header count
	Rows    []RowVM
}

// DashboardVM is the full dashboard page model.
type DashboardVM struct {
	Chrome   ChromeVM
	Hosts    []string // host filter options, local first
	Groups   []GroupVM
	FlatRows []RowVM
	Summary  string // "N of M containers · K updates"
	Empty    bool
	EmptyMsg string
}

// AgentCardVM is one agent's card on the agents page.
type AgentCardVM struct {
	Name         string
	ReachClass   string // "ok", "down", or "nodocker"
	ReachLabel   string // "reachable", "unreachable", or "Docker unavailable"
	LastPoll     time.Time
	CertNotAfter time.Time
	Flags        []string // warn-flag texts
}

// AgentsVM is the full agents page model.
type AgentsVM struct {
	Chrome ChromeVM
	Cards  []AgentCardVM
	Empty  bool
}

// FieldVM is one labeled input on an auth form.
type FieldVM struct {
	ID           string
	Label        string
	Type         string // "text" or "password"
	Name         string
	Autocomplete string
	Value        string
	Error        string
}

// SetupVM is the first-run setup page model.
type SetupVM struct {
	Theme  string
	Fields []FieldVM
}

// LoginVM is the login page model.
type LoginVM struct {
	Theme  string
	Banner string // generic top-of-card error, never field-specific
	Fields []FieldVM
}

// deriveState resolves a row's version-cell state. The republished
// check is a per-row join: shared check digest vs this container's
// own running index digest, so one image can split across hosts.
func deriveState(c inventory.Container, ch store.CheckResult, found bool) DisplayState {
	if ch.Kind == "LOCAL" {
		return StateLocal
	}
	if !found || ch.CheckedAt.IsZero() {
		return StatePending
	}
	switch ch.Status {
	case store.StatusAuthRequired:
		return StateAuth
	case store.StatusRateLimited:
		return StateRate
	}
	if ch.Kind == "SEMVER" && ch.Latest != "" {
		return StateUpdate
	}
	if ch.Kind == "DIGEST" && ch.RegistryDigest != "" && ch.RegistryDigest != runningIndexDigest(c, ch.Ref) {
		return StateRepublished
	}
	return StateCurrent
}
