package httpd

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/elexation/dockwatch/internal/auth"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/elexation/dockwatch/internal/web"
)

const (
	dockerReadTimeout = 5 * time.Second
	minPasswordLen    = 8
)

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

	hash, err := auth.Hash(pw)
	if err != nil {
		s.fail(w, "hash password", err)
		return
	}
	if err := s.cfg.Store.PutAdmin(store.Admin{Username: username, Hash: hash, CreatedAt: s.now()}); err != nil {
		s.fail(w, "store admin", err)
		return
	}
	if err := s.startSession(w, username); err != nil {
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
		pwErr = "Password is required."
	case len(pw) < minPasswordLen:
		pwErr = "Password must be at least 8 characters."
	}
	if pwErr == "" && confirm != pw {
		confirmErr = "Passwords don't match."
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
		match, verr := auth.Verify(admin.Hash, pw)
		ok = verr == nil && match && username == admin.Username
	}
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.renderLogin(w, web.LoginVM{Theme: themeFrom(r), Banner: "Incorrect username or password", Fields: loginFields(username)})
		return
	}
	if err := s.startSession(w, admin.Username); err != nil {
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
	vm := web.BuildDashboard([]inventory.Inventory{inv}, checks, web.DashboardInput{
		LocalName:        s.cfg.LocalName,
		Theme:            themeFrom(r),
		Layout:           "grouped",
		LastCycle:        latestCheck(checks),
		NotificationsOff: s.cfg.NotificationsOff,
		RepublishedSince: s.republishedSince(checks),
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
	vm := web.BuildAgents(agents, web.AgentsInput{
		Theme:            themeFrom(r),
		LastCycle:        latestPoll(agents),
		NotificationsOff: s.cfg.NotificationsOff,
	})
	if err := s.cfg.Renderer.RenderAgents(w, vm); err != nil {
		slog.Error("render agents", "err", err)
	}
}

// --- helpers ---

func (s *Server) adminExists() bool {
	exists, err := s.cfg.Store.AdminExists()
	if err != nil {
		slog.Error("check admin", "err", err)
		return false
	}
	return exists
}

// republishedSince reads each DIGEST republish date from the notified bucket (D18).
func (s *Server) republishedSince(checks []store.CheckResult) map[string]time.Time {
	out := make(map[string]time.Time)
	for _, ch := range checks {
		if ch.Kind != "DIGEST" {
			continue
		}
		if n, found, err := s.cfg.Store.GetNotified(ch.Ref); err == nil && found && !n.NotifiedAt.IsZero() {
			out[ch.Ref] = n.NotifiedAt
		}
	}
	return out
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

// fail logs err and returns a bare 500, leaking no detail.
func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	slog.Error("web "+what, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// themeFrom reads the theme cookie, defaulting to "auto".
func themeFrom(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil {
		switch c.Value {
		case "auto", "light", "dark":
			return c.Value
		}
	}
	return "auto"
}

func setupFields(username, userErr, pwErr, confirmErr string) []web.FieldVM {
	return []web.FieldVM{
		{ID: "setup-user", Label: "Username", Type: "text", Name: "username", Autocomplete: "username", Value: username, Error: userErr},
		{ID: "setup-pw", Label: "Password", Type: "password", Name: "password", Autocomplete: "new-password", Error: pwErr},
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
