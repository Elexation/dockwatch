package web

import (
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

// fixedNow anchors every relative time so render output is deterministic.
var fixedNow = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return fixedNow.Add(-d) }

func testRenderer() *Renderer {
	r, err := newRenderer(func() time.Time { return fixedNow })
	if err != nil {
		panic(err)
	}
	return r
}

// sampleDashboard returns a fixture exercising every display state, the
// same-image-two-hosts republished split, and both watch-gate exclusions
// (non-running and dw.watch=false).
func sampleDashboard() ([]inventory.Inventory, []store.CheckResult, DashboardInput) {
	home := inventory.Inventory{
		V: 1, Host: "home", Docker: inventory.DockerOK,
		Containers: []inventory.Container{
			running("gitea", "gitea/gitea:1.24.3", "gitea/gitea@sha256:g1", "healthy"),
			running("vaultwarden", "vaultwarden/server:1.30.1", "vaultwarden/server@sha256:v1", "healthy"),
			running("nginx-edge", "nginx:stable", "nginx@sha256:old", "healthy"),
			running("backups", "ghcr.io/example/backups:1.0", "ghcr.io/example/backups@sha256:b1", ""),
			labeled("ignored", "ignored:1.0", "running", map[string]string{"dw.watch": "false"}),
			labeled("stopped", "stopped:1.0", "exited", nil),
		},
	}
	server := inventory.Inventory{
		V: 1, Host: "server", Docker: inventory.DockerOK,
		Containers: []inventory.Container{
			running("postgres", "postgres:16.2", "postgres@sha256:p1", "healthy"),
			running("traefik", "traefik:v3.1.0", "traefik@sha256:t1", "healthy"),
			running("redis", "redis:7.2-alpine", "redis@sha256:r1", "healthy"),
			running("uptime-kuma", "louislam/uptime-kuma:1", "louislam/uptime-kuma@sha256:u1", "healthy"),
			running("nginx-cache", "nginx:stable", "nginx@sha256:new", "healthy"),
			running("jellyfin", "jellyfin/jellyfin:latest", "jellyfin/jellyfin@sha256:jold", "healthy"),
		},
	}
	pi4 := inventory.Inventory{
		V: 1, Host: "pi4", Docker: inventory.DockerOK,
		Containers: []inventory.Container{
			local("my-dashboard", "my-dashboard:dev", "starting"),
			running("plex", "plexinc/pms:1.40", "plexinc/pms@sha256:x1", ""),
			running("pihole", "pihole/pihole:2024.07.0", "pihole/pihole@sha256:h1", "unhealthy"),
		},
	}

	checks := []store.CheckResult{
		semverUpdate("gitea/gitea:1.24.3", "1.24.3", "1.25.0", "minor"),
		semverCurrent("vaultwarden/server:1.30.1", "1.30.1"),
		digest("nginx:stable", "sha256:new"),
		// "backups" has no check entry, so it resolves to pending.
		semverUpdate("postgres:16.2", "16.2", "17.0", "major"),
		semverUpdate("traefik:v3.1.0", "v3.1.0", "v3.1.2", "patch"),
		semverCurrent("redis:7.2-alpine", "7.2-alpine"),
		status("louislam/uptime-kuma:1", "DIGEST", store.StatusRateLimited),
		digest("jellyfin/jellyfin:latest", "sha256:jnew"),
		localCheck("my-dashboard:dev"),
		status("plexinc/pms:1.40", "SEMVER", store.StatusAuthRequired),
		semverCurrent("pihole/pihole:2024.07.0", "2024.07.0"),
	}

	in := DashboardInput{
		LocalName:        "home",
		Theme:            "auto",
		Layout:           "grouped",
		LastCycle:        ago(5 * time.Minute),
		NotificationsOff: true,
		RepublishedSince: map[string]time.Time{
			"nginx:stable":             ago(72 * time.Hour),
			"jellyfin/jellyfin:latest": ago(26 * time.Hour),
		},
	}
	return []inventory.Inventory{home, server, pi4}, checks, in
}

func sampleAgents() ([]store.AgentStatus, AgentsInput) {
	agents := []store.AgentStatus{
		{Name: "server", LastOK: true, LastPoll: ago(time.Minute), CertNotAfter: date(2026, 8, 19), LastWireV: 2},
		{Name: "backup", LastOK: true, LastPoll: ago(5 * time.Minute), CertNotAfter: date(2031, 3, 4), LastRenewalReminder: ago(24 * time.Hour)},
		{Name: "pi4", LastOK: false, LastPoll: ago(2 * time.Hour), CertNotAfter: date(2030, 11, 22)},
		{Name: "nas", LastOK: true, LastPoll: ago(41 * time.Minute), CertNotAfter: date(2031, 1, 15)},
	}
	in := AgentsInput{
		Theme:            "auto",
		LastCycle:        ago(5 * time.Minute),
		NotificationsOff: true,
		DockerStatus:     map[string]string{"nas": inventory.DockerUnavailable},
	}
	return agents, in
}

func setupClean() SetupVM {
	return SetupVM{Theme: "auto", Fields: setupFields("", "", "")}
}

func setupErrors() SetupVM {
	f := setupFields("Username is required.", "", "Passwords don't match.")
	return SetupVM{Theme: "auto", Fields: f}
}

func loginClean() LoginVM {
	return LoginVM{Theme: "auto", Fields: loginFields()}
}

func loginBanner() LoginVM {
	return LoginVM{Theme: "auto", Banner: "Incorrect username or password", Fields: loginFields()}
}

func setupFields(userErr, pwErr, confirmErr string) []FieldVM {
	return []FieldVM{
		{ID: "setup-user", Label: "Username", Type: "text", Name: "username", Autocomplete: "username", Error: userErr},
		{ID: "setup-pw", Label: "Password", Type: "password", Name: "password", Autocomplete: "new-password", Error: pwErr},
		{ID: "setup-pw2", Label: "Confirm password", Type: "password", Name: "confirm", Autocomplete: "new-password", Error: confirmErr},
	}
}

func loginFields() []FieldVM {
	return []FieldVM{
		{ID: "login-user", Label: "Username", Type: "text", Name: "username", Autocomplete: "username"},
		{ID: "login-pw", Label: "Password", Type: "password", Name: "password", Autocomplete: "current-password"},
	}
}

// --- container/check builders ---

func running(name, image, repoDigest, health string) inventory.Container {
	return inventory.Container{
		Name: name, Image: image, State: "running",
		RepoDigests: []string{repoDigest}, Health: health,
	}
}

func local(name, image, health string) inventory.Container {
	return inventory.Container{Name: name, Image: image, State: "running", Health: health}
}

func labeled(name, image, state string, labels map[string]string) inventory.Container {
	return inventory.Container{Name: name, Image: image, State: state, Labels: labels}
}

func semverUpdate(ref, cur, latest, bump string) store.CheckResult {
	return store.CheckResult{Ref: ref, Kind: "SEMVER", Current: cur, Latest: latest, UpdateKind: bump, Status: store.StatusOK, CheckedAt: ago(2 * time.Hour)}
}

func semverCurrent(ref, cur string) store.CheckResult {
	return store.CheckResult{Ref: ref, Kind: "SEMVER", Current: cur, Status: store.StatusOK, CheckedAt: ago(2 * time.Hour)}
}

func digest(ref, registryDigest string) store.CheckResult {
	return store.CheckResult{Ref: ref, Kind: "DIGEST", RegistryDigest: registryDigest, Status: store.StatusOK, CheckedAt: ago(2 * time.Hour)}
}

func localCheck(ref string) store.CheckResult {
	return store.CheckResult{Ref: ref, Kind: "LOCAL", Status: store.StatusOK, CheckedAt: ago(2 * time.Hour)}
}

func status(ref, kind string, st store.CheckStatus) store.CheckResult {
	return store.CheckResult{Ref: ref, Kind: kind, Status: st, CheckedAt: ago(6 * time.Hour)}
}

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
