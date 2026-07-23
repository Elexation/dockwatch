package web

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

var bannedGlyphs = []string{string(rune(0x2014)), string(rune(0x2013)), string(rune(0x00a7))}

func assertNoBannedGlyph(t *testing.T, label, s string) {
	t.Helper()
	for _, g := range bannedGlyphs {
		if strings.Contains(s, g) {
			t.Errorf("%s contains banned glyph %q", label, g)
		}
	}
}

func assertContains(t *testing.T, label, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("%s: missing %q", label, n)
		}
	}
}

func TestDeriveState(t *testing.T) {
	cases := []struct {
		name  string
		c     inventory.Container
		ch    store.CheckResult
		found bool
		want  DisplayState
	}{
		{"local", local("x", "x:dev", ""), store.CheckResult{Kind: "LOCAL", CheckedAt: fixedNow}, true, StateLocal},
		{"pending-missing", running("x", "x:1", "x@sha256:a", ""), store.CheckResult{}, false, StatePending},
		{"pending-zerotime", running("x", "x:1", "x@sha256:a", ""), store.CheckResult{Kind: "SEMVER"}, true, StatePending},
		{"auth", running("x", "ns/x:1", "ns/x@sha256:a", ""), store.CheckResult{Ref: "ns/x:1", Kind: "SEMVER", Status: store.StatusAuthRequired, CheckedAt: fixedNow}, true, StateAuth},
		{"auth-bare-name-is-local", running("x", "x:1", "x@sha256:a", ""), store.CheckResult{Ref: "x:1", Kind: "DIGEST", Status: store.StatusAuthRequired, CheckedAt: fixedNow}, true, StateLocal},
		{"rate", running("x", "x:1", "x@sha256:a", ""), store.CheckResult{Kind: "DIGEST", Status: store.StatusRateLimited, CheckedAt: fixedNow}, true, StateRate},
		{"update", running("x", "x:1", "x@sha256:a", ""), store.CheckResult{Kind: "SEMVER", Latest: "2", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateUpdate},
		{"current-semver", running("x", "x:1", "x@sha256:a", ""), store.CheckResult{Kind: "SEMVER", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateCurrent},
		{"republished", running("x", "x:stable", "x@sha256:old", ""), store.CheckResult{Ref: "x:stable", Kind: "DIGEST", RegistryDigest: "sha256:new", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateRepublished},
		{"current-digest", running("x", "x:stable", "x@sha256:new", ""), store.CheckResult{Ref: "x:stable", Kind: "DIGEST", RegistryDigest: "sha256:new", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateCurrent},
		{"semver-republished", running("x", "x:1.2.3", "x@sha256:old", ""), store.CheckResult{Ref: "x:1.2.3", Kind: "SEMVER", RegistryDigest: "sha256:new", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateRepublished},
		{"semver-update-beats-republish", running("x", "x:1.2.3", "x@sha256:old", ""), store.CheckResult{Ref: "x:1.2.3", Kind: "SEMVER", Latest: "1.3.0", RegistryDigest: "sha256:new", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateUpdate},
		{"semver-current-same-digest", running("x", "x:1.2.3", "x@sha256:idx", ""), store.CheckResult{Ref: "x:1.2.3", Kind: "SEMVER", RegistryDigest: "sha256:idx", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateCurrent},
		{"local-beats-checked", local("x", "x:dev", ""), store.CheckResult{Kind: "LOCAL", Status: store.StatusOK, CheckedAt: fixedNow}, true, StateLocal},
	}
	for _, tc := range cases {
		if got := deriveState(tc.c, tc.ch, tc.found); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBuildDashboardGroupsAndSort(t *testing.T) {
	invs, checks, in := sampleDashboard()
	vm := BuildDashboard(invs, checks, in)

	if vm.Empty {
		t.Fatal("dashboard unexpectedly empty")
	}
	if got := len(vm.FlatRows); got != 13 {
		t.Errorf("watch gate: got %d rows, want 13 (ignored + stopped excluded)", got)
	}
	wantHosts := []string{"home", "server", "pi4"}
	if got := hostNames(vm.Groups); !equal(got, wantHosts) {
		t.Errorf("group order: got %v, want %v", got, wantHosts)
	}
	wantSummary := "13 of 13 containers " + string(rune(0x00b7)) + " 3 updates"
	if vm.Summary != wantSummary {
		t.Errorf("summary: got %q, want %q", vm.Summary, wantSummary)
	}

	home := vm.Groups[0]
	if home.Count != 4 || home.Updates != 1 {
		t.Errorf("home group: count=%d updates=%d, want 4/1", home.Count, home.Updates)
	}
	if got := rowNames(home.Rows); !equal(got, []string{"gitea", "nginx-edge", "vaultwarden", "backups"}) {
		t.Errorf("home row order: got %v", got)
	}

	server := vm.Groups[1]
	if got := rowNames(server.Rows); !equal(got, []string{"postgres", "traefik", "jellyfin", "uptime-kuma", "nginx-cache", "redis"}) {
		t.Errorf("server row order: got %v", got)
	}
}

func TestBuildDashboardStress(t *testing.T) {
	invs, checks, in := stressDashboard()
	vm := BuildDashboard(invs, checks, in)
	if got := len(vm.FlatRows); got != 55 {
		t.Errorf("stress rows = %d, want 55", got)
	}
	wantSummary := "55 of 55 containers " + string(rune(0x00b7)) + " 14 updates"
	if vm.Summary != wantSummary {
		t.Errorf("summary: got %q, want %q", vm.Summary, wantSummary)
	}
	wg := findRow(vm.FlatRows, "wg-easy")
	if wg == nil || wg.State != "republished" {
		t.Fatalf("wg-easy (SEMVER pinned-tag republish): got %+v, want republished", wg)
	}
	if wg.RepublishedAt.IsZero() {
		t.Error("wg-easy republished date missing")
	}
	if wg.RepublishedEstimated {
		t.Error("wg-easy date should be the registry's, not estimated")
	}
	sc := findRow(vm.FlatRows, "scrutiny")
	if sc == nil || !sc.RepublishedEstimated {
		t.Fatalf("scrutiny should carry an estimated republish date, got %+v", sc)
	}
}

func TestRepublishedSplit(t *testing.T) {
	invs, checks, in := sampleDashboard()
	vm := BuildDashboard(invs, checks, in)
	edge := findRow(vm.FlatRows, "nginx-edge")
	cache := findRow(vm.FlatRows, "nginx-cache")
	if edge == nil || cache == nil {
		t.Fatal("nginx rows missing")
	}
	if edge.State != "republished" {
		t.Errorf("nginx-edge (running old digest): got %q, want republished", edge.State)
	}
	if cache.State != "current" {
		t.Errorf("nginx-cache (running new digest): got %q, want current", cache.State)
	}
}

func TestBareNameAuthRendersLocal(t *testing.T) {
	invs := []inventory.Inventory{{
		V: 1, Host: "home", Docker: inventory.DockerOK,
		Containers: []inventory.Container{
			running("dockwatch", "dockwatch", "dockwatch@sha256:self", "healthy"),
			running("plex", "plexinc/pms:1.40", "plexinc/pms@sha256:x1", ""),
		},
	}}
	checks := []store.CheckResult{
		status("dockwatch", "DIGEST", store.StatusAuthRequired),
		status("plexinc/pms:1.40", "SEMVER", store.StatusAuthRequired),
	}
	vm := BuildDashboard(invs, checks, DashboardInput{})
	dw := findRow(vm.FlatRows, "dockwatch")
	if dw == nil || dw.State != "local" {
		t.Errorf("bare-name auth ref: got %+v, want state local", dw)
	}
	plex := findRow(vm.FlatRows, "plex")
	if plex == nil || plex.State != "auth" {
		t.Errorf("namespaced auth ref: got %+v, want state auth", plex)
	}
}

func TestBuildAgents(t *testing.T) {
	agents, in := sampleAgents()
	vm := BuildAgents(agents, in)
	if vm.Empty {
		t.Fatal("agents unexpectedly empty")
	}
	byName := map[string]AgentCardVM{}
	for _, c := range vm.Cards {
		byName[c.Name] = c
	}
	if byName["server"].ReachClass != "ok" {
		t.Errorf("server reach: got %q", byName["server"].ReachClass)
	}
	if byName["pi4"].ReachClass != "down" {
		t.Errorf("pi4 reach: got %q", byName["pi4"].ReachClass)
	}
	if byName["nas"].ReachClass != "nodocker" {
		t.Errorf("nas reach: got %q", byName["nas"].ReachClass)
	}
	if len(byName["server"].Flags) != 1 || !strings.Contains(byName["server"].Flags[0], "agent is newer") {
		t.Errorf("server flags: %v", byName["server"].Flags)
	}
	if len(byName["backup"].Flags) != 1 || !strings.Contains(byName["backup"].Flags[0], "Renewed bundle not yet installed") {
		t.Errorf("backup flags: %v", byName["backup"].Flags)
	}
	if len(byName["pi4"].Flags) != 0 {
		t.Errorf("pi4 flags: %v", byName["pi4"].Flags)
	}
}

func TestBuildAgentsEmpty(t *testing.T) {
	vm := BuildAgents(nil, AgentsInput{})
	if !vm.Empty {
		t.Error("nil agents should be empty")
	}
}

func TestRenderDashboard(t *testing.T) {
	r := testRenderer()
	invs, checks, in := sampleDashboard()
	var buf bytes.Buffer
	if err := r.RenderDashboard(&buf, BuildDashboard(invs, checks, in)); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	assertContains(t, "dashboard", out,
		"DockWatch", "gitea/<wbr>gitea", "1.25.0", "republished 3d ago",
		"republished · detected 1d ago",
		"up to date", "local, not checkable", "auth required, not checkable",
		"check delayed (rate limited)", "not checked yet",
		"13 of 13 containers",
		`data-theme="dark"`, `aria-label="Switch to light theme"`, "dw-themeglyph",
		"Notifications disabled.", "<wbr>")
	if strings.Contains(out, "ignored:1.0") || strings.Contains(out, "stopped:1.0") {
		t.Error("watch-gated container leaked into render")
	}
	assertNoBannedGlyph(t, "dashboard", out)
}

func TestRenderDashboardChecking(t *testing.T) {
	r := testRenderer()
	invs, checks, in := sampleDashboard()
	in.Checking = true
	var buf bytes.Buffer
	if err := r.RenderDashboard(&buf, BuildDashboard(invs, checks, in)); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	assertContains(t, "checking dashboard", out,
		"last cycle: running…", "Checking…", "dw-spin", "data-dw-checking", " disabled")
	assertNoBannedGlyph(t, "checking dashboard", out)
}

func TestRenderDashboardFilterHooks(t *testing.T) {
	r := testRenderer()
	invs, checks, in := sampleDashboard()
	var buf bytes.Buffer
	if err := r.RenderDashboard(&buf, BuildDashboard(invs, checks, in)); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	assertContains(t, "filter hooks", out,
		`data-state="update"`, `data-state="republished"`, `data-host="home"`,
		"data-dw-noresults", "Nothing matches the current filters.")
	if strings.Contains(out, "data-dw-checking") {
		t.Error("idle dashboard rendered the checking button state")
	}
}

func TestRenderDashboardEmpty(t *testing.T) {
	r := testRenderer()
	var buf bytes.Buffer
	if err := r.RenderDashboard(&buf, BuildDashboard(nil, nil, DashboardInput{Theme: "dark", Layout: "grouped"})); err != nil {
		t.Fatalf("render: %v", err)
	}
	assertContains(t, "empty dashboard", buf.String(),
		"No containers found", "Nothing is running yet on the configured hosts.")
	assertNoBannedGlyph(t, "empty dashboard", buf.String())
}

func TestRenderAgents(t *testing.T) {
	r := testRenderer()
	agents, in := sampleAgents()
	var buf bytes.Buffer
	if err := r.RenderAgents(&buf, BuildAgents(agents, in)); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	assertContains(t, "agents", out,
		"Agents", "machines DockWatch polls, defined in config, read-only here",
		"reachable", "unreachable", "Docker unavailable",
		"expires 2026-08-19", "Last successful poll",
		"Update hub: agent is newer (agent v2, hub v1).",
		"Renewed bundle not yet installed. Agent still serving the previous certificate.")
	assertNoBannedGlyph(t, "agents", out)
}

func TestRenderAgentsEmpty(t *testing.T) {
	r := testRenderer()
	var buf bytes.Buffer
	if err := r.RenderAgents(&buf, BuildAgents(nil, AgentsInput{Theme: "dark"})); err != nil {
		t.Fatalf("render: %v", err)
	}
	assertContains(t, "empty agents", buf.String(),
		"No machines configured", "DockWatch is watching this host only.")
	assertNoBannedGlyph(t, "empty agents", buf.String())
}

func TestRenderSetup(t *testing.T) {
	r := testRenderer()
	var clean, errs bytes.Buffer
	if err := r.RenderSetup(&clean, setupClean()); err != nil {
		t.Fatalf("render clean: %v", err)
	}
	assertContains(t, "setup", clean.String(),
		"Create account", "First-run setup, create the admin account for this install.",
		"This screen only appears once, while no account exists yet.",
		`autocomplete="new-password"`)
	assertNoBannedGlyph(t, "setup", clean.String())

	if err := r.RenderSetup(&errs, setupErrors()); err != nil {
		t.Fatalf("render errors: %v", err)
	}
	assertContains(t, "setup errors", errs.String(),
		"Username is required.", "Passwords don&#39;t match.", `aria-invalid="true"`)
	assertNoBannedGlyph(t, "setup errors", errs.String())
}

func TestRenderLogin(t *testing.T) {
	r := testRenderer()
	var clean, banner bytes.Buffer
	if err := r.RenderLogin(&clean, loginClean()); err != nil {
		t.Fatalf("render clean: %v", err)
	}
	assertContains(t, "login", clean.String(),
		"Sign in", "Sign in to your DockWatch instance.", `autocomplete="current-password"`)
	assertNoBannedGlyph(t, "login", clean.String())

	if err := r.RenderLogin(&banner, loginBanner()); err != nil {
		t.Fatalf("render banner: %v", err)
	}
	assertContains(t, "login banner", banner.String(),
		"Incorrect username or password", `role="alert"`)
	assertNoBannedGlyph(t, "login banner", banner.String())
}

func TestStaticAssetsNoBannedGlyph(t *testing.T) {
	sub, err := StaticFS()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dw-harbor.css", "app.js"} {
		b, err := fs.ReadFile(sub, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		assertNoBannedGlyph(t, name, string(b))
	}
}

func TestRelativeTime(t *testing.T) {
	base := fixedNow
	cases := []struct {
		t    time.Time
		want string
	}{
		{time.Time{}, ""},
		{base.Add(-30 * time.Second), "just now"},
		{base.Add(-5 * time.Minute), "5m ago"},
		{base.Add(-2 * time.Hour), "2h ago"},
		{base.Add(-3 * 24 * time.Hour), "3d ago"},
	}
	for _, tc := range cases {
		if got := relativeTime(base, tc.t); got != tc.want {
			t.Errorf("relativeTime(%v): got %q, want %q", tc.t, got, tc.want)
		}
	}
}

// --- helpers ---

func hostNames(gs []GroupVM) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Host
	}
	return out
}

func rowNames(rs []RowVM) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

func findRow(rs []RowVM, name string) *RowVM {
	for i := range rs {
		if rs[i].Name == name {
			return &rs[i]
		}
	}
	return nil
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
