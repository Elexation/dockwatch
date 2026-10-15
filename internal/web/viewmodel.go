// Package web is the hub's render layer: it maps inventories and stored check
// results into view models and renders the embedded templates and static
// assets. It is render-only and deliberately depends on inventory and store
// alone; HTTP serving, sessions, and auth live in package httpd.
package web

import (
	"strings"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

// DisplayState is the resolved version-cell state for one row; the constants
// are ordered by the dashboard's default sort rank, lower sorting first.
type DisplayState int

const (
	StateUpdate      DisplayState = iota // a newer tag matching the dw.tags filter (or the scheme heuristic) exists
	StateRepublished                     // the pinned tag's registry index digest moved
	StateChecking                        // live, JS-only; the builder never emits it
	StateRate                            // registry rate-limited the check
	StateError                           // the check failed (a registry error, an invalid dw.tags regex)
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
	case StateError:
		return "error"
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

// ChromeVM is the shared app-page chrome (header plus notifications notice).
type ChromeVM struct {
	Active           string // nav key ("dashboard", "agents", "settings"); drives aria-current
	Theme            string // "light" or "dark"; dark is the default
	Layout           string // "grouped" or "flat"; dashboard only
	LastCycle        time.Time
	NotificationsOff bool
	Checking         bool // busy header: disabled button, "running…" cycle text
}

// RowVM is one container row on the dashboard.
type RowVM struct {
	Host                 string
	Name                 string
	Image                string
	State                string // DisplayState.String(), for the template switch
	From                 string // SEMVER: running version
	To                   string // SEMVER: newest available version
	Bump                 string // "major", "minor", "patch", or "" when not computable
	RepublishedAt        time.Time
	RepublishedEstimated bool   // date is the hub's first-seen time, not the registry's
	Err                  string // StateError: why the check failed
	Health               string // "healthy", "unhealthy", "starting", or "" for none
	Checked              time.Time
	Stale                bool      // host unreachable: the row is a last-known snapshot
	LastSeen             time.Time // that host's last successful poll, shown in place of Checked

	rank DisplayState // unexported: the sort key
}

// GroupVM is one host's card in the grouped dashboard view.
type GroupVM struct {
	Host     string
	Count    int
	Updates  int       // rows in StateUpdate, for the accent header count
	Stale    bool      // host unreachable: the rows are a last-known snapshot
	LastSeen time.Time // that host's last successful poll
	Rows     []RowVM
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
	// DockerDown lists hosts whose Docker daemon did not answer, in the last
	// inventory that got through. They have no rows, hence no group or stale
	// marker, so without a notice they would just vanish.
	DockerDown []HostNoticeVM
}

// HostNoticeVM is a dashboard notice for a host whose containers cannot be listed.
type HostNoticeVM struct {
	Host     string
	Stale    bool      // the host is also unreachable now; Docker was down when last seen
	LastSeen time.Time // that host's last successful poll, when Stale
}

// AgentCardVM is one agent's card on the agents page.
type AgentCardVM struct {
	Name         string
	ReachClass   string // "ok", "down", or "nodocker"
	ReachLabel   string // "reachable", "unreachable", or "Docker unavailable"
	LastSuccess  time.Time
	CertNotAfter time.Time
	Flags        []string // warn-flag texts
}

// AgentsVM is the full agents page model.
type AgentsVM struct {
	Chrome ChromeVM
	Cards  []AgentCardVM
	Empty  bool
}

// SettingsVM is the settings page model; its only section is the password change.
type SettingsVM struct {
	Chrome ChromeVM
	Banner string // generic top-of-section error, never field-specific
	Done   bool   // success confirmation, rendered on a fresh form
	Fields []FieldVM
}

// FieldVM is one labeled input on an auth form.
type FieldVM struct {
	ID           string
	Label        string
	Type         string // "text" or "password"
	Name         string
	Autocomplete string
	Value        string
	Hint         string // constraint shown before submit, e.g. a minimum length
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
// It applies to DIGEST and SEMVER alike (a pinned tag can be republished
// too); a newer tag outranks it.
func deriveState(c inventory.Container, ch store.CheckResult, found bool) DisplayState {
	if ch.Kind == "LOCAL" {
		return StateLocal
	}
	if !found || ch.CheckedAt.IsZero() {
		return StatePending
	}
	switch ch.Status {
	case store.StatusAuthRequired:
		// A bare name can only be a Docker Hub official image, and those are
		// always public, so auth-required proves a local build. (Containerd-store
		// hosts stamp repo digests on local builds, defeating the LOCAL classifier.)
		if !strings.Contains(ch.Ref, "/") {
			return StateLocal
		}
		return StateAuth
	case store.StatusRateLimited:
		return StateRate
	case store.StatusError:
		return StateError
	}
	if ch.Kind == "SEMVER" && ch.Latest != "" {
		return StateUpdate
	}
	// A container with no repo digest is a local build or loaded image sharing
	// the ref with a pulled one. The notifier's join treats it as unknown, so a
	// DIGEST verdict here would claim a currency nothing proves.
	run := runningIndexDigest(c, ch.Ref)
	if run == "" && ch.Kind == "DIGEST" {
		return StateLocal
	}
	if ch.RegistryDigest != "" && run != "" && run != ch.RegistryDigest {
		return StateRepublished
	}
	return StateCurrent
}
