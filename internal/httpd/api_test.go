package httpd

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func newAPIServer(t *testing.T, mod func(*Config)) (*Server, *store.Store) {
	t.Helper()
	sum := sha256.Sum256([]byte(testToken))
	return newTestServerWith(t, false, func(c *Config) {
		c.APITokenSHA256 = sum[:]
		if mod != nil {
			mod(c)
		}
	})
}

func apiDo(s *Server, method, target, authz string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeStatus(t *testing.T, rec *httptest.ResponseRecorder) statusResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/status: code=%d body=%s, want 200", rec.Code, rec.Body)
	}
	var got statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return got
}

func TestAPIAbsentWithoutToken(t *testing.T) {
	s, _ := newTestServer(t, false)
	for _, method := range []string{"GET", "POST"} {
		target := "/api/v1/status"
		if method == "POST" {
			target = "/api/v1/check"
		}
		if rec := apiDo(s, method, target, "Bearer "+testToken); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s without a configured token: code=%d, want 404", method, target, rec.Code)
		}
	}
}

func TestAPIRejectsBadCredentials(t *testing.T) {
	calls := 0
	s, st := newAPIServer(t, func(c *Config) { c.Trigger = func() { calls++ } })
	cookie := loginSession(t, s, st)
	cases := []struct {
		name, target, authz string
		cookie              *http.Cookie
	}{
		{"no header", "/api/v1/status", "", nil},
		{"wrong token", "/api/v1/status", "Bearer " + strings.Repeat("f", len(testToken)), nil},
		{"basic scheme", "/api/v1/status", "Basic " + testToken, nil},
		{"scheme only", "/api/v1/status", "Bearer", nil},
		{"query string", "/api/v1/status?token=" + url.QueryEscape(testToken), "", nil},
		{"session cookie", "/api/v1/status", "", cookie},
		{"trigger without token", "/api/v1/check", "", cookie},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := "GET"
			if strings.HasSuffix(tc.target, "/check") {
				method = "POST"
			}
			var cookies []*http.Cookie
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			rec := apiDo(s, method, tc.target, tc.authz, cookies...)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("code=%d, want 401", rec.Code)
			}
			if rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Location") != "" {
				t.Errorf("headers = %v, want a Bearer challenge and no redirect", rec.Header())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Error("a refused API request set a cookie")
			}
		})
	}
	if calls != 0 {
		t.Errorf("trigger called %d times by refused requests, want 0", calls)
	}
}

func TestAPIAcceptsLowercaseScheme(t *testing.T) {
	s, _ := newAPIServer(t, nil)
	decodeStatus(t, apiDo(s, "GET", "/api/v1/status", "bearer "+testToken))
}

func TestAPIStatus(t *testing.T) {
	checked := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	done := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	seen := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC)
	local := inventory.Inventory{V: 1, Host: "local", Docker: inventory.DockerOK, Containers: []inventory.Container{
		{Name: "gitea", Image: "gitea/gitea:1.24.3", State: "running", RepoDigests: []string{"gitea/gitea@sha256:aaa"}},
		{Name: "web", Image: "nginx", State: "running", RepoDigests: []string{"nginx@sha256:bbb"}},
		{Name: "skipped", Image: "acme/skip:1.0.0", State: "running", Labels: map[string]string{"dw.watch": "false"}},
	}}
	remote := inventory.Inventory{V: 1, Host: "pi4", Docker: inventory.DockerOK, Containers: []inventory.Container{
		{Name: "remote", Image: "gitea/gitea:1.24.3", State: "running", RepoDigests: []string{"gitea/gitea@sha256:aaa"}},
	}}
	s, st := newAPIServer(t, func(c *Config) {
		c.Local = fakeReader{inv: local}
		c.AgentInventories = func() []inventory.Inventory { return []inventory.Inventory{remote} }
		c.LastCycleDone = func() time.Time { return done }
	})
	for _, ch := range []store.CheckResult{
		{Ref: inventory.Ref("gitea/gitea:1.24.3"), Kind: "SEMVER", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor", Status: store.StatusOK, CheckedAt: checked},
		{Ref: inventory.Ref("nginx"), Kind: "DIGEST", RegistryDigest: "sha256:bbb", Status: store.StatusOK, CheckedAt: checked},
	} {
		if err := st.PutCheck(ch); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []store.AgentStatus{
		{Name: "pi4", LastOK: false, LastPoll: done, LastSuccess: seen, ConsecutiveFailures: 3},
		{Name: "nas", LastOK: false, LastPoll: done, ConsecutiveFailures: 9}, // never reached
	} {
		if err := st.PutAgent(a); err != nil {
			t.Fatal(err)
		}
	}

	rec := apiDo(s, "GET", "/api/v1/status", "Bearer "+testToken)
	got := decodeStatus(t, rec)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("API request set a cookie")
	}
	if !got.LastCycle.Equal(done) || got.Checking {
		t.Errorf("last_cycle=%s checking=%v, want %s and false", got.LastCycle, got.Checking, done)
	}

	wantHosts := []apiHost{
		{Name: "local", Reachable: true, Docker: "ok"},
		{Name: "nas", Reachable: false},
		{Name: "pi4", Reachable: false, LastSeen: seen, Docker: "ok"},
	}
	if len(got.Hosts) != len(wantHosts) {
		t.Fatalf("hosts = %+v, want %+v", got.Hosts, wantHosts)
	}
	for i, h := range wantHosts {
		g := got.Hosts[i]
		if g.Name != h.Name || g.Reachable != h.Reachable || !g.LastSeen.Equal(h.LastSeen) || g.Docker != h.Docker {
			t.Errorf("hosts[%d] = %+v, want %+v", i, g, h)
		}
	}

	if got.Counts["update"] != 2 || got.Counts["current"] != 1 || len(got.Counts) != 2 {
		t.Errorf("counts = %v, want update:2 current:1", got.Counts)
	}
	if len(got.Containers) != 3 {
		t.Fatalf("containers = %+v, want 3 (the dw.watch=false one excluded)", got.Containers)
	}
	gitea, remoteRow, web := got.Containers[0], got.Containers[1], got.Containers[2]
	if gitea.Name != "gitea" || gitea.State != "update" || gitea.Current != "1.24.3" || gitea.Latest != "1.25.0" || gitea.Bump != "minor" || gitea.Stale {
		t.Errorf("gitea row = %+v", gitea)
	}
	if !gitea.CheckedAt.Equal(checked) {
		t.Errorf("gitea checked_at = %s, want %s", gitea.CheckedAt, checked)
	}
	if remoteRow.Host != "pi4" || remoteRow.State != "update" || !remoteRow.Stale {
		t.Errorf("remote row = %+v, want a stale update on pi4", remoteRow)
	}
	if web.Name != "web" || web.State != "current" || web.Latest != "" {
		t.Errorf("web row = %+v, want current with no versions", web)
	}

	// Zero and empty fields are omitted rather than sent as zero values.
	body := rec.Body.String()
	for _, absent := range []string{`"republished_at"`, `"error"`, `"0001-01-01`} {
		if strings.Contains(body, absent) {
			t.Errorf("body contains %s: %s", absent, body)
		}
	}
}

func TestAPIStatusEmptyBeforeFirstCycle(t *testing.T) {
	s, _ := newAPIServer(t, func(c *Config) {
		c.Local = fakeReader{inv: inventory.Inventory{V: 1, Host: "local", Docker: inventory.DockerUnavailable}}
	})
	rec := apiDo(s, "GET", "/api/v1/status", "Bearer "+testToken)
	got := decodeStatus(t, rec)
	if len(got.Hosts) != 1 || got.Hosts[0].Docker != "unavailable" {
		t.Errorf("hosts = %+v, want the local host with Docker unavailable", got.Hosts)
	}
	body := rec.Body.String()
	for _, want := range []string{`"containers":[]`, `"counts":{}`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"last_cycle"`) {
		t.Errorf("body has last_cycle before any cycle: %s", body)
	}
}

func TestAPIStatusFailsOnStoreError(t *testing.T) {
	s, st := newAPIServer(t, nil)
	st.Close()
	rec := apiDo(s, "GET", "/api/v1/status", "Bearer "+testToken)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, want 500 rather than an empty list", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"containers"`) {
		t.Errorf("error body carries a container list: %s", rec.Body)
	}
}

func TestAPICheckCooldownAndConflict(t *testing.T) {
	calls, running := 0, false
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	done := time.Date(2026, 7, 13, 11, 0, 0, 0, time.UTC)
	s, _ := newAPIServer(t, func(c *Config) {
		c.Trigger = func() { calls++ }
		c.CheckRunning = func() bool { return running }
		c.LastCycleDone = func() time.Time { return done }
		c.Now = func() time.Time { return now }
	})
	post := func() *httptest.ResponseRecorder { return apiDo(s, "POST", "/api/v1/check", "Bearer "+testToken) }

	rec := post()
	if rec.Code != http.StatusAccepted || calls != 1 {
		t.Fatalf("first trigger: code=%d calls=%d, want 202 and 1", rec.Code, calls)
	}
	var tr triggerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil || !tr.LastCycle.Equal(done) {
		t.Errorf("trigger body = %s (err %v), want last_cycle %s", rec.Body, err, done)
	}

	now = now.Add(time.Minute)
	rec = post()
	if rec.Code != http.StatusTooManyRequests || calls != 1 {
		t.Fatalf("trigger in cooldown: code=%d calls=%d, want 429 and still 1", rec.Code, calls)
	}
	if ra := rec.Header().Get("Retry-After"); ra != "240" {
		t.Errorf("Retry-After = %q, want 240", ra)
	}

	now = now.Add(4 * time.Minute)
	if rec = post(); rec.Code != http.StatusAccepted || calls != 2 {
		t.Fatalf("trigger after cooldown: code=%d calls=%d, want 202 and 2", rec.Code, calls)
	}

	// A refusal while a cycle runs must not spend the cooldown.
	now = now.Add(10 * time.Minute)
	running = true
	if rec = post(); rec.Code != http.StatusConflict || calls != 2 {
		t.Fatalf("trigger mid-cycle: code=%d calls=%d, want 409 and still 2", rec.Code, calls)
	}
	running = false
	if rec = post(); rec.Code != http.StatusAccepted || calls != 3 {
		t.Fatalf("trigger after the cycle: code=%d calls=%d, want 202 and 3", rec.Code, calls)
	}
}

func TestAPICheckUnavailableWithoutScheduler(t *testing.T) {
	s, _ := newAPIServer(t, nil)
	if rec := apiDo(s, "POST", "/api/v1/check", "Bearer "+testToken); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d, want 503", rec.Code)
	}
}

func TestAPICooldownLeavesCheckNowUnthrottled(t *testing.T) {
	calls := 0
	s, st := newAPIServer(t, func(c *Config) { c.Trigger = func() { calls++ } })
	cookie := loginSession(t, s, st)
	if rec := apiDo(s, "POST", "/api/v1/check", "Bearer "+testToken); rec.Code != http.StatusAccepted {
		t.Fatalf("API trigger: code=%d, want 202", rec.Code)
	}
	for i := range 2 {
		if rec := do(s, "POST", "/check", nil, cookie); rec.Code != http.StatusAccepted {
			t.Fatalf("UI check now #%d: code=%d, want 202", i+1, rec.Code)
		}
	}
	if calls != 3 {
		t.Errorf("trigger called %d times, want 3", calls)
	}
}

func TestAPICheckRejectsCrossOriginBrowser(t *testing.T) {
	calls := 0
	s, _ := newAPIServer(t, func(c *Config) { c.Trigger = func() { calls++ } })
	req := httptest.NewRequest("POST", "/api/v1/check", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("cross-site POST: code=%d calls=%d, want 403 and 0", rec.Code, calls)
	}
}
