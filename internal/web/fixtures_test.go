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

// stressDashboard extends sampleDashboard to a 55-row fleet on the same three
// hosts: the filters, both layouts, and the SEMVER republish at scale.
func stressDashboard() ([]inventory.Inventory, []store.CheckResult, DashboardInput) {
	invs, checks, in := sampleDashboard()

	homeExtra := []inventory.Container{
		running("home-assistant", "ghcr.io/home-assistant/home-assistant:2026.5.3", "ghcr.io/home-assistant/home-assistant@sha256:ha1", "healthy"),
		running("mosquitto", "eclipse-mosquitto:2.0.21", "eclipse-mosquitto@sha256:mq1", ""),
		running("zigbee2mqtt", "koenkk/zigbee2mqtt:1.42.0", "koenkk/zigbee2mqtt@sha256:z2m1", "healthy"),
		running("node-red", "nodered/node-red:4.0.9", "nodered/node-red@sha256:nr1", "healthy"),
		running("esphome", "ghcr.io/esphome/esphome:2026.5.2", "ghcr.io/esphome/esphome@sha256:esp1", ""),
		running("grafana", "grafana/grafana:11.6.0", "grafana/grafana@sha256:gf1", "healthy"),
		running("prometheus", "prom/prometheus:v3.3.0", "prom/prometheus@sha256:pm1", "healthy"),
		running("loki", "grafana/loki:3.5.0", "grafana/loki@sha256:lk1", "healthy"),
		running("influxdb", "influxdb:2.7.11", "influxdb@sha256:ifx1", "healthy"),
		running("adguardhome", "adguard/adguardhome:v0.107.61", "adguard/adguardhome@sha256:agh1", "healthy"),
		running("unbound", "klutchell/unbound:1.22.0", "klutchell/unbound@sha256:ub1", ""),
		running("wg-easy", "ghcr.io/wg-easy/wg-easy:14", "ghcr.io/wg-easy/wg-easy@sha256:wg1", "healthy"),
		running("homarr", "ghcr.io/homarr-labs/homarr:1.18.1", "ghcr.io/homarr-labs/homarr@sha256:hm1", "healthy"),
		running("ntfy", "binwiederhier/ntfy:v2.12.0", "binwiederhier/ntfy@sha256:nt1", "healthy"),
		running("freshrss", "freshrss/freshrss:1.26.2", "freshrss/freshrss@sha256:fr1", "healthy"),
		running("syncthing", "syncthing/syncthing:1.29.6", "syncthing/syncthing@sha256:st1", "healthy"),
	}
	serverExtra := []inventory.Container{
		running("sonarr", "lscr.io/linuxserver/sonarr:4.0.14", "lscr.io/linuxserver/sonarr@sha256:sn1", "healthy"),
		running("radarr", "lscr.io/linuxserver/radarr:5.21.1", "lscr.io/linuxserver/radarr@sha256:rd1", "healthy"),
		running("prowlarr", "lscr.io/linuxserver/prowlarr:1.35.1", "lscr.io/linuxserver/prowlarr@sha256:pw1", "healthy"),
		running("bazarr", "lscr.io/linuxserver/bazarr:1.5.2", "lscr.io/linuxserver/bazarr@sha256:bz1", "healthy"),
		running("qbittorrent", "lscr.io/linuxserver/qbittorrent:5.0.4", "lscr.io/linuxserver/qbittorrent@sha256:qb1", "healthy"),
		running("overseerr", "sctx/overseerr:1.34.0", "sctx/overseerr@sha256:ov1", "unhealthy"),
		running("tautulli", "tautulli/tautulli:v2.15.2", "tautulli/tautulli@sha256:tt1", "healthy"),
		running("navidrome", "deluan/navidrome:0.55.2", "deluan/navidrome@sha256:nv1", "healthy"),
		running("audiobookshelf", "ghcr.io/advplyr/audiobookshelf:2.21.0", "ghcr.io/advplyr/audiobookshelf@sha256:ab1", "healthy"),
		running("calibre-web", "lscr.io/linuxserver/calibre-web:0.6.24", "lscr.io/linuxserver/calibre-web@sha256:cw1", ""),
		running("paperless-ngx", "ghcr.io/paperless-ngx/paperless-ngx:2.15.3", "ghcr.io/paperless-ngx/paperless-ngx@sha256:pp1", "healthy"),
		running("minio", "minio/minio:latest", "minio/minio@sha256:mnold", "healthy"),
		running("mariadb", "mariadb:11.4.5", "mariadb@sha256:mdb1", "healthy"),
		running("mongo", "mongo:8.0.9", "mongo@sha256:mg1", "healthy"),
		running("authentik", "ghcr.io/goauthentik/server:2026.4.1", "ghcr.io/goauthentik/server@sha256:ak1", "healthy"),
		running("nginx-proxy-manager", "jc21/nginx-proxy-manager:2.12.3", "jc21/nginx-proxy-manager@sha256:npm1", "healthy"),
		running("gotify", "gotify/server:2.6.1", "gotify/server@sha256:gt1", "healthy"),
		running("miniflux", "miniflux/miniflux:2.2.8", "miniflux/miniflux@sha256:mf1", "healthy"),
		running("searxng", "searxng/searxng:latest", "searxng/searxng@sha256:sxold", "healthy"),
		running("backup-runner", "registry.lan/backup-runner:1.4", "registry.lan/backup-runner@sha256:br1", ""),
	}
	pi4Extra := []inventory.Container{
		running("octoprint", "octoprint/octoprint:1.10.3", "octoprint/octoprint@sha256:op1", "healthy"),
		running("homebridge", "homebridge/homebridge:2025-05-20", "homebridge/homebridge@sha256:hb1", "healthy"),
		running("tailscale", "tailscale/tailscale:v1.84.0", "tailscale/tailscale@sha256:ts1", ""),
		running("cloudflared", "cloudflare/cloudflared:2026.5.1", "cloudflare/cloudflared@sha256:cf1", "healthy"),
		running("scrutiny", "ghcr.io/analogj/scrutiny:master-omnibus", "ghcr.io/analogj/scrutiny@sha256:scold", "starting"),
		local("pi-vpn", "pi-vpn:local", ""),
	}
	invs[0].Containers = append(invs[0].Containers, homeExtra...)
	invs[1].Containers = append(invs[1].Containers, serverExtra...)
	invs[2].Containers = append(invs[2].Containers, pi4Extra...)

	checks = append(checks,
		semverUpdate("ghcr.io/home-assistant/home-assistant:2026.5.3", "2026.5.3", "2026.6.0", "minor"),
		semverCurrent("eclipse-mosquitto:2.0.21", "2.0.21"),
		semverUpdate("koenkk/zigbee2mqtt:1.42.0", "1.42.0", "2.0.0", "major"),
		semverCurrent("nodered/node-red:4.0.9", "4.0.9"),
		semverCurrent("ghcr.io/esphome/esphome:2026.5.2", "2026.5.2"),
		semverUpdate("grafana/grafana:11.6.0", "11.6.0", "12.0.1", "major"),
		semverCurrent("prom/prometheus:v3.3.0", "v3.3.0"),
		semverCurrent("grafana/loki:3.5.0", "3.5.0"),
		semverCurrent("influxdb:2.7.11", "2.7.11"),
		semverUpdate("adguard/adguardhome:v0.107.61", "v0.107.61", "v0.107.62", "patch"),
		semverCurrent("klutchell/unbound:1.22.0", "1.22.0"),
		semverRepublished("ghcr.io/wg-easy/wg-easy:14", "14", "sha256:wg2"),
		semverCurrent("ghcr.io/homarr-labs/homarr:1.18.1", "1.18.1"),
		semverCurrent("binwiederhier/ntfy:v2.12.0", "v2.12.0"),
		semverUpdate("freshrss/freshrss:1.26.2", "1.26.2", "1.26.3", "patch"),
		semverCurrent("syncthing/syncthing:1.29.6", "1.29.6"),
		semverUpdate("lscr.io/linuxserver/sonarr:4.0.14", "4.0.14", "4.0.15", "patch"),
		semverCurrent("lscr.io/linuxserver/radarr:5.21.1", "5.21.1"),
		semverCurrent("lscr.io/linuxserver/prowlarr:1.35.1", "1.35.1"),
		semverCurrent("lscr.io/linuxserver/bazarr:1.5.2", "1.5.2"),
		semverUpdate("lscr.io/linuxserver/qbittorrent:5.0.4", "5.0.4", "5.1.0", "minor"),
		semverCurrent("sctx/overseerr:1.34.0", "1.34.0"),
		semverCurrent("tautulli/tautulli:v2.15.2", "v2.15.2"),
		semverUpdate("deluan/navidrome:0.55.2", "0.55.2", "0.56.0", "minor"),
		semverCurrent("ghcr.io/advplyr/audiobookshelf:2.21.0", "2.21.0"),
		semverCurrent("lscr.io/linuxserver/calibre-web:0.6.24", "0.6.24"),
		semverUpdate("ghcr.io/paperless-ngx/paperless-ngx:2.15.3", "2.15.3", "2.16.0", "minor"),
		digest("minio/minio:latest", "sha256:mnnew"),
		semverCurrent("mariadb:11.4.5", "11.4.5"),
		semverCurrent("mongo:8.0.9", "8.0.9"),
		semverUpdate("ghcr.io/goauthentik/server:2026.4.1", "2026.4.1", "2026.5.0", "minor"),
		semverCurrent("jc21/nginx-proxy-manager:2.12.3", "2.12.3"),
		semverCurrent("gotify/server:2.6.1", "2.6.1"),
		semverCurrent("miniflux/miniflux:2.2.8", "2.2.8"),
		digest("searxng/searxng:latest", "sha256:sxnew"),
		status("registry.lan/backup-runner:1.4", "SEMVER", store.StatusAuthRequired),
		semverCurrent("octoprint/octoprint:1.10.3", "1.10.3"),
		status("homebridge/homebridge:2025-05-20", "SEMVER", store.StatusRateLimited),
		semverUpdate("tailscale/tailscale:v1.84.0", "v1.84.0", "v1.84.2", "patch"),
		semverCurrent("cloudflare/cloudflared:2026.5.1", "2026.5.1"),
		digest("ghcr.io/analogj/scrutiny:master-omnibus", "sha256:scnew"),
		localCheck("pi-vpn:local"),
	)

	in.RepublishedSince["ghcr.io/wg-easy/wg-easy:14"] = ago(72 * time.Hour)
	in.RepublishedSince["minio/minio:latest"] = ago(96 * time.Hour)
	in.RepublishedSince["searxng/searxng:latest"] = ago(12 * time.Hour)
	in.RepublishedSince["ghcr.io/analogj/scrutiny:master-omnibus"] = ago(120 * time.Hour)
	return invs, checks, in
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

func semverRepublished(ref, cur, registryDigest string) store.CheckResult {
	return store.CheckResult{Ref: ref, Kind: "SEMVER", Current: cur, RegistryDigest: registryDigest, Status: store.StatusOK, CheckedAt: ago(2 * time.Hour)}
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
