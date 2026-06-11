package httpd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elexation/dockwatch/internal/auth"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/elexation/dockwatch/internal/web"
)

type fakeReader struct{ inv inventory.Inventory }

func (f fakeReader) Read(context.Context) (inventory.Inventory, error) { return f.inv, nil }

func newTestServer(t *testing.T, secure bool) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	r, err := web.NewRenderer()
	if err != nil {
		t.Fatalf("web.NewRenderer: %v", err)
	}
	sfs, err := web.StaticFS()
	if err != nil {
		t.Fatalf("web.StaticFS: %v", err)
	}
	inv := inventory.Inventory{V: 1, Host: "local", Docker: inventory.DockerOK, Containers: []inventory.Container{}}
	s := New(Config{
		Renderer:         r,
		Store:            st,
		Local:            fakeReader{inv: inv},
		StaticFS:         sfs,
		LocalName:        "local",
		NotificationsOff: true,
		SecureCookie:     secure,
	})
	return s, st
}

func seedAdmin(t *testing.T, st *store.Store, user, pw string) {
	t.Helper()
	h, err := auth.Hash(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := st.PutAdmin(store.Admin{Username: user, Hash: h, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("PutAdmin: %v", err)
	}
}

func do(s *Server, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func sessionCookieOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, to string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
		t.Fatalf("code=%d loc=%q, want 303 -> %s", rec.Code, rec.Header().Get("Location"), to)
	}
}

func TestFreshInstallRoutesToSetup(t *testing.T) {
	s, _ := newTestServer(t, false)
	wantRedirect(t, do(s, "GET", "/", nil), "/setup")

	rec := do(s, "GET", "/setup", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /setup: code=%d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Create account") {
		t.Error("setup page missing 'Create account'")
	}
}

func TestSetupCreatesAdminThenLocks(t *testing.T) {
	s, st := newTestServer(t, false)

	form := url.Values{"username": {"admin"}, "password": {"hunter2pass"}, "confirm": {"hunter2pass"}}
	rec := do(s, "POST", "/setup", form)
	wantRedirect(t, rec, "/")
	cookie := sessionCookieOf(rec)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("POST /setup did not set a session cookie")
	}
	if exists, _ := st.AdminExists(); !exists {
		t.Fatal("admin not created")
	}
	// Self-destructed: GET /setup now redirects to /login.
	wantRedirect(t, do(s, "GET", "/setup", nil), "/login")
	// The fresh session reaches the dashboard.
	if rec := do(s, "GET", "/", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("GET / with session: code=%d, want 200", rec.Code)
	}
}

func TestSetupRejectsMismatch(t *testing.T) {
	s, st := newTestServer(t, false)
	form := url.Values{"username": {"admin"}, "password": {"hunter2pass"}, "confirm": {"different1"}}
	rec := do(s, "POST", "/setup", form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /setup mismatch: code=%d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Passwords don&#39;t match.") {
		t.Error("missing mismatch error")
	}
	if exists, _ := st.AdminExists(); exists {
		t.Error("admin created despite validation failure")
	}
}

func TestSetupRejectsShortPassword(t *testing.T) {
	s, _ := newTestServer(t, false)
	form := url.Values{"username": {"admin"}, "password": {"short"}, "confirm": {"short"}}
	rec := do(s, "POST", "/setup", form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "at least 8 characters") {
		t.Error("missing short-password error")
	}
}

func TestLoginFlow(t *testing.T) {
	s, st := newTestServer(t, false)
	seedAdmin(t, st, "admin", "hunter2pass")

	if rec := do(s, "GET", "/login", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Fatalf("GET /login: code=%d", rec.Code)
	}

	rec := do(s, "POST", "/login", url.Values{"username": {"admin"}, "password": {"wrongpass1"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: code=%d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Incorrect username or password") {
		t.Error("missing login banner")
	}
	if c := sessionCookieOf(rec); c != nil && c.Value != "" {
		t.Error("bad login set a session cookie")
	}

	rec = do(s, "POST", "/login", url.Values{"username": {"admin"}, "password": {"hunter2pass"}})
	wantRedirect(t, rec, "/")
	if c := sessionCookieOf(rec); c == nil || c.Value == "" {
		t.Fatal("good login set no session cookie")
	}
}

func TestGateRedirectsUnauthenticated(t *testing.T) {
	s, st := newTestServer(t, false)
	seedAdmin(t, st, "admin", "hunter2pass")
	for _, path := range []string{"/", "/agents"} {
		wantRedirect(t, do(s, "GET", path, nil), "/login")
	}
}

func TestLogout(t *testing.T) {
	s, st := newTestServer(t, false)
	seedAdmin(t, st, "admin", "hunter2pass")
	cookie := sessionCookieOf(do(s, "POST", "/login", url.Values{"username": {"admin"}, "password": {"hunter2pass"}}))
	if cookie == nil {
		t.Fatal("no session after login")
	}

	wantRedirect(t, do(s, "POST", "/logout", nil, cookie), "/login")
	if _, found, _ := st.GetSession(cookie.Value); found {
		t.Error("session not deleted on logout")
	}
	wantRedirect(t, do(s, "GET", "/", nil, cookie), "/login")
}

func TestResetAdminInvalidatesSessions(t *testing.T) {
	s, st := newTestServer(t, false)
	seedAdmin(t, st, "admin", "hunter2pass")
	cookie := sessionCookieOf(do(s, "POST", "/login", url.Values{"username": {"admin"}, "password": {"hunter2pass"}}))
	if cookie == nil {
		t.Fatal("no session after login")
	}

	// Simulate the DW_RESET_ADMIN startup path.
	if err := st.DeleteAdmin(); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearSessions(); err != nil {
		t.Fatal(err)
	}

	if _, found, _ := st.GetSession(cookie.Value); found {
		t.Error("session survived reset")
	}
	// Admin wiped: the old cookie is rejected and setup is re-armed.
	wantRedirect(t, do(s, "GET", "/", nil, cookie), "/setup")
}

func TestCookieFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
	}{
		{"plain-or-proxied", false},
		{"https-or-trusted-proxy", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, st := newTestServer(t, tc.secure)
			seedAdmin(t, st, "admin", "hunter2pass")
			c := sessionCookieOf(do(s, "POST", "/login", url.Values{"username": {"admin"}, "password": {"hunter2pass"}}))
			if c == nil {
				t.Fatal("no session cookie")
			}
			if !c.HttpOnly {
				t.Error("cookie not HttpOnly")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("SameSite = %v, want Strict", c.SameSite)
			}
			if c.Secure != tc.secure {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.secure)
			}
		})
	}
}

func TestStaticServed(t *testing.T) {
	s, _ := newTestServer(t, false)
	if rec := do(s, "GET", "/static/dw-harbor.css", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /static/dw-harbor.css: code=%d, want 200", rec.Code)
	}
}
