package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/elexation/dockwatch/internal/web"
)

const (
	dockerReadTimeout = 5 * time.Second
	minPasswordLen    = 8
	passwordRequired  = "Password is required."
	passwordMismatch  = "Passwords don't match."
	badHashMsg        = "stored admin password hash is unreadable; set DW_RESET_ADMIN=true to re-run setup"
)

// Both strings derive from minPasswordLen so the hint cannot drift from the rule.
var (
	passwordHint     = fmt.Sprintf("At least %d characters.", minPasswordLen)
	passwordTooShort = fmt.Sprintf("Password must be at least %d characters.", minPasswordLen)
)

// passwordErrors is what the settings page shows for each code a rejected
// password change redirects with.
var passwordErrors = map[string]struct{ banner, pwErr, confirmErr string }{
	"current":   {banner: "Current password is incorrect"},
	"busy":      {banner: busyBanner},
	"throttled": {banner: "Too many failed attempts, wait a minute and try again"},
	"required":  {pwErr: passwordRequired},
	"short":     {pwErr: passwordTooShort},
	"same":      {pwErr: "New password must differ from the current one."},
	"mismatch":  {confirmErr: passwordMismatch},
}

// --- first-run setup ---

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	if s.adminExists() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderSetup(w, web.SetupVM{Theme: themeFrom(r), Fields: setupFields("", "", "", "")})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if s.adminExists() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")

	userErr, pwErr, confirmErr := validateSetup(username, pw, confirm)
	if userErr != "" || pwErr != "" || confirmErr != "" {
		w.WriteHeader(http.StatusBadRequest)
		s.renderSetup(w, web.SetupVM{Theme: themeFrom(r), Fields: setupFields(username, userErr, pwErr, confirmErr)})
		return
	}

	hash, err := s.guard.hash(r.Context(), pw)
	if code, _ := refusal(w, err); code != 0 {
		http.Error(w, http.StatusText(code), code)
		return
	}
	if err != nil {
		s.fail(w, "hash password", err)
		return
	}
	admin := store.Admin{Username: username, Hash: hash, CreatedAt: s.now()}
	if err := s.cfg.Store.CreateAdmin(admin); err != nil {
		if errors.Is(err, store.ErrAdminExists) {
			slog.Warn("first-run setup refused: a concurrent setup already created the admin")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.fail(w, "store admin", err)
		return
	}
	// The startup log said setup was open to anyone; record when it closed.
	slog.Info("admin account created; first-run setup closed", "username", username)
	if err := s.startSession(w, admin); err != nil {
		s.fail(w, "start session", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func validateSetup(username, pw, confirm string) (userErr, pwErr, confirmErr string) {
	if username == "" {
		userErr = "Username is required."
	}
	switch {
	case pw == "":
		pwErr = passwordRequired
	case utf8.RuneCountInString(pw) < minPasswordLen:
		pwErr = passwordTooShort
	}
	if pwErr == "" && confirm != pw {
		confirmErr = passwordMismatch
	}
	return
}

// --- login / logout ---

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if !s.adminExists() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, web.LoginVM{Theme: themeFrom(r), Fields: loginFields("")})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.adminExists() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")

	admin, found, err := s.cfg.Store.GetAdmin()
	if err != nil {
		s.fail(w, "read admin", err)
		return
	}
	// Verify even on a wrong username, so timing does not leak account existence.
	ok := false
	if found {
		match, verr := s.guard.verify(r.Context(), admin.Hash, pw)
		if code, banner := refusal(w, verr); code != 0 {
			w.WriteHeader(code)
			s.renderLogin(w, web.LoginVM{Theme: themeFrom(r), Banner: banner, Fields: loginFields(username)})
			return
		}
		if verr != nil {
			slog.Error(badHashMsg, "err", verr)
		}
		ok = verr == nil && match && username == admin.Username
	}
	if !ok {
		s.guard.failed()
		w.WriteHeader(http.StatusUnauthorized)
		s.renderLogin(w, web.LoginVM{Theme: themeFrom(r), Banner: "Incorrect username or password", Fields: loginFields(username)})
		return
	}
	s.guard.succeeded()
	if err := s.startSession(w, admin); err != nil {
		s.fail(w, "start session", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = s.cfg.Store.DeleteSession(c.Value)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- settings ---

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	e := passwordErrors[q.Get("err")]
	s.renderSettings(w, web.SettingsVM{
		Chrome: s.chrome(r, "settings"),
		Done:   q.Get("changed") == "1",
		Banner: e.banner,
		Fields: passwordFields("", e.pwErr, e.confirmErr),
	})
}

// passwordSubmit rewrites the admin hash and bumps its epoch, which invalidates
// every existing session at once, then reissues this one. A change made because
// the old password leaked therefore evicts whoever had it, without signing the
// operator out of the page they are on. Every outcome redirects rather than
// renders: app.js reloads after a check cycle, and reloading a POST response
// would resubmit the form.
func (s *Server) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	current := r.PostFormValue("current")
	pw := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")

	admin, found, err := s.cfg.Store.GetAdmin()
	if err != nil {
		s.fail(w, "read admin", err)
		return
	}
	if !found {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	// Shares the login's failure count: a stolen session must not become a
	// second, unthrottled way to guess the password.
	match, verr := s.guard.verify(r.Context(), admin.Hash, current)
	if code := refusalCode(verr); code != "" {
		settingsError(w, r, code)
		return
	}
	if verr != nil || !match {
		s.guard.failed()
		if verr != nil {
			slog.Error(badHashMsg, "err", verr)
		} else {
			slog.Warn("password change rejected: wrong current password")
		}
		settingsError(w, r, "current")
		return
	}
	s.guard.succeeded()

	if code := validatePassword(pw, confirm, current); code != "" {
		settingsError(w, r, code)
		return
	}

	hash, err := s.guard.hash(r.Context(), pw)
	if code := refusalCode(err); code != "" {
		settingsError(w, r, code)
		return
	}
	if err != nil {
		s.fail(w, "hash password", err)
		return
	}
	// Conditional on the epoch read above, so two racing changes cannot both
	// land on the same new epoch and each keep its own session alive.
	admin, err = s.cfg.Store.ChangePassword(admin.Epoch, hash)
	if errors.Is(err, store.ErrAdminChanged) {
		// The other change's epoch bump already ended this session.
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, "store admin", err)
		return
	}
	slog.Info("admin password changed; other sessions signed out")
	// Old sessions are already dead by epoch; this only drops their records.
	if err := s.cfg.Store.ClearSessions(); err != nil {
		slog.Warn("clear sessions after password change", "err", err)
	}
	if err := s.startSession(w, admin); err != nil {
		s.fail(w, "start session", err)
		return
	}
	http.Redirect(w, r, "/settings?changed=1", http.StatusSeeOther)
}

// settingsError sends a rejected password change back to the settings page.
func settingsError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/settings?err="+code, http.StatusSeeOther)
}

// validatePassword checks a new password against the length rule, its confirmation,
// and the one it replaces, returning a passwordErrors code; "" if it passes.
// current is compared so a no-op change cannot look like one.
func validatePassword(pw, confirm, current string) string {
	switch {
	case pw == "":
		return "required"
	case utf8.RuneCountInString(pw) < minPasswordLen:
		return "short"
	case pw == current:
		return "same"
	case confirm != pw:
		return "mismatch"
	}
	return ""
}

func passwordFields(currentErr, pwErr, confirmErr string) []web.FieldVM {
	return []web.FieldVM{
		{ID: "pw-current", Label: "Current password", Type: "password", Name: "current", Autocomplete: "current-password", Error: currentErr},
		{ID: "pw-new", Label: "New password", Type: "password", Name: "password", Autocomplete: "new-password", Hint: passwordHint, Error: pwErr},
		{ID: "pw-confirm", Label: "Confirm new password", Type: "password", Name: "confirm", Autocomplete: "new-password", Error: confirmErr},
	}
}

// --- check now ---

func (s *Server) checkNow(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Trigger == nil {
		http.Error(w, "manual checks unavailable", http.StatusServiceUnavailable)
		return
	}
	s.cfg.Trigger()
	w.WriteHeader(http.StatusAccepted)
}

// checkStatus reports the scheduler's cycle state; app.js polls it after a
// manual check and reloads once lastCycle advances.
func (s *Server) checkStatus(w http.ResponseWriter, r *http.Request) {
	st := struct {
		Running   bool   `json:"running"`
		LastCycle string `json:"lastCycle"`
	}{Running: s.checking()}
	if s.cfg.LastCycleDone != nil {
		if t := s.cfg.LastCycleDone(); !t.IsZero() {
			st.LastCycle = t.UTC().Format(time.RFC3339Nano)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(st); err != nil {
		slog.Error("write check status", "err", err)
	}
}

// --- protected pages ---

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), dockerReadTimeout)
	defer cancel()
	inv, err := s.cfg.Local.Read(ctx)
	if err != nil {
		slog.Warn("local docker read failed", "err", err)
	}
	checks, err := s.cfg.Store.AllChecks()
	if err != nil {
		slog.Error("read checks", "err", err)
	}
	invs := []inventory.Inventory{inv}
	invs = append(invs, s.agentInventories()...)
	vm := web.BuildDashboard(invs, checks, web.DashboardInput{
		LocalName:        s.cfg.LocalName,
		Theme:            themeFrom(r),
		Layout:           layoutFrom(r),
		LastCycle:        s.lastCycle(latestCheck(checks)),
		NotificationsOff: s.cfg.NotificationsOff,
		Checking:         s.checking(),
		StaleHosts:       s.staleHosts(),
	})
	if err := s.cfg.Renderer.RenderDashboard(w, vm); err != nil {
		slog.Error("render dashboard", "err", err)
	}
}

func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.cfg.Store.AllAgents()
	if err != nil {
		slog.Error("read agents", "err", err)
	}
	docker := make(map[string]string)
	for _, inv := range s.agentInventories() {
		docker[inv.Host] = inv.Docker
	}
	vm := web.BuildAgents(agents, web.AgentsInput{
		Theme:            themeFrom(r),
		LastCycle:        s.lastCycle(latestPoll(agents)),
		NotificationsOff: s.cfg.NotificationsOff,
		Checking:         s.checking(),
		DockerStatus:     docker,
	})
	if err := s.cfg.Renderer.RenderAgents(w, vm); err != nil {
		slog.Error("render agents", "err", err)
	}
}

// --- helpers ---

// chrome builds the shared header model for pages that render no data of their
// own. active is matched against the nav links and the settings cog, so a value
// naming none of them simply leaves all three unmarked.
func (s *Server) chrome(r *http.Request, active string) web.ChromeVM {
	return web.ChromeVM{
		Active:           active,
		Theme:            themeFrom(r),
		LastCycle:        s.lastCycle(time.Time{}),
		NotificationsOff: s.cfg.NotificationsOff,
		Checking:         s.checking(),
	}
}

// adminExists reports whether setup has run. A store error reads as true, so
// the unauthenticated setup page stays shut rather than failing open.
func (s *Server) adminExists() bool {
	exists, err := s.cfg.Store.AdminExists()
	if err != nil {
		slog.Error("check admin", "err", err)
		return true
	}
	return exists
}

// checking reports whether a check cycle is in flight; false without a scheduler.
func (s *Server) checking() bool {
	return s.cfg.CheckRunning != nil && s.cfg.CheckRunning()
}

// lastCycle prefers the scheduler's completion stamp, which advances even
// when a cycle persisted nothing; fallback covers a fresh restart from
// persisted state.
func (s *Server) lastCycle(fallback time.Time) time.Time {
	if s.cfg.LastCycleDone != nil {
		if t := s.cfg.LastCycleDone(); !t.IsZero() {
			return t
		}
	}
	return fallback
}

// staleHosts maps each unreachable agent to its last successful poll. The
// poller keeps serving a down agent's last-known inventory, so without this the
// dashboard would render those containers as if they were just checked.
func (s *Server) staleHosts() map[string]time.Time {
	agents, err := s.cfg.Store.AllAgents()
	if err != nil {
		slog.Error("read agents", "err", err)
		return nil
	}
	out := make(map[string]time.Time, len(agents))
	for _, a := range agents {
		if !a.LastOK {
			out[a.Name] = a.LastSuccess
		}
	}
	return out
}

// agentInventories returns the poller's last-known agent inventories; empty without a poller.
func (s *Server) agentInventories() []inventory.Inventory {
	if s.cfg.AgentInventories == nil {
		return nil
	}
	return s.cfg.AgentInventories()
}

func (s *Server) renderSetup(w http.ResponseWriter, vm web.SetupVM) {
	if err := s.cfg.Renderer.RenderSetup(w, vm); err != nil {
		slog.Error("render setup", "err", err)
	}
}

func (s *Server) renderLogin(w http.ResponseWriter, vm web.LoginVM) {
	if err := s.cfg.Renderer.RenderLogin(w, vm); err != nil {
		slog.Error("render login", "err", err)
	}
}

func (s *Server) renderSettings(w http.ResponseWriter, vm web.SettingsVM) {
	if err := s.cfg.Renderer.RenderSettings(w, vm); err != nil {
		slog.Error("render settings", "err", err)
	}
}

// fail logs err and returns a bare 500, leaking no detail.
func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	slog.Error("web "+what, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// themeFrom reads the theme cookie; anything but "light", including a stale
// "auto", falls back to the dark default.
func themeFrom(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && c.Value == "light" {
		return "light"
	}
	return "dark"
}

// layoutFrom reads the layout cookie; anything but "flat" falls back to the grouped default.
func layoutFrom(r *http.Request) string {
	if c, err := r.Cookie(layoutCookie); err == nil && c.Value == "flat" {
		return "flat"
	}
	return "grouped"
}

func setupFields(username, userErr, pwErr, confirmErr string) []web.FieldVM {
	return []web.FieldVM{
		{ID: "setup-user", Label: "Username", Type: "text", Name: "username", Autocomplete: "username", Value: username, Error: userErr},
		{ID: "setup-pw", Label: "Password", Type: "password", Name: "password", Autocomplete: "new-password", Hint: passwordHint, Error: pwErr},
		{ID: "setup-pw2", Label: "Confirm password", Type: "password", Name: "confirm", Autocomplete: "new-password", Error: confirmErr},
	}
}

func loginFields(username string) []web.FieldVM {
	return []web.FieldVM{
		{ID: "login-user", Label: "Username", Type: "text", Name: "username", Autocomplete: "username", Value: username},
		{ID: "login-pw", Label: "Password", Type: "password", Name: "password", Autocomplete: "current-password"},
	}
}

func latestCheck(checks []store.CheckResult) time.Time {
	var latest time.Time
	for _, ch := range checks {
		if ch.CheckedAt.After(latest) {
			latest = ch.CheckedAt
		}
	}
	return latest
}

func latestPoll(agents []store.AgentStatus) time.Time {
	var latest time.Time
	for _, a := range agents {
		if a.LastPoll.After(latest) {
			latest = a.LastPoll
		}
	}
	return latest
}
