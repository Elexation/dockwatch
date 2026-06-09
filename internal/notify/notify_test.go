package notify

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/store"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// capturedReq is one publish the fake ntfy server received.
type capturedReq struct {
	path string
	hdr  http.Header
	body string
}

// fakeNtfy is an in-memory ntfy server that records every publish and can be
// flipped to fail so delivery-failure handling is testable.
type fakeNtfy struct {
	mu   sync.Mutex
	reqs []capturedReq
	fail bool
	srv  *httptest.Server
}

func newFakeNtfy(t *testing.T) *fakeNtfy {
	t.Helper()
	f := &fakeNtfy{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, capturedReq{path: r.URL.Path, hdr: r.Header.Clone(), body: string(b)})
		fail := f.fail
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNtfy) setFail(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }

func (f *fakeNtfy) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }

func (f *fakeNtfy) last() capturedReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

func (f *fakeNtfy) client(topic string) *Client {
	return NewClient(f.srv.URL, topic, "", f.srv.Client())
}

func (f *fakeNtfy) notifier(st *store.Store, domain string, staged func(string) (time.Time, bool)) *Notifier {
	return NewNotifier(f.client("topic"), st, quietLogger(), domain, staged)
}

func TestUpdateNewerTagFiresOnceThenSilent(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	in := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor", Hosts: []string{"home"}}
	now := time.Now()

	n.NotifyUpdates(context.Background(), []UpdateInput{in}, now)
	if f.count() != 1 {
		t.Fatalf("publishes = %d, want 1", f.count())
	}
	if got, want := f.last().body, "gitea 1.24.3 → 1.25.0 (minor) on home"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	state, found, _ := st.GetNotified(in.Ref)
	if !found || state.Version != "1.25.0" {
		t.Errorf("stored = %+v found=%v, want Version 1.25.0", state, found)
	}

	n.NotifyUpdates(context.Background(), []UpdateInput{in}, now)
	if f.count() != 1 {
		t.Errorf("publishes = %d after repeat, want 1 (notify-once)", f.count())
	}
}

func TestUpdateShowsNewestNotIntermediate(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	ref := "gitea/gitea:1.24.3"
	// The operator was already told about 1.25.0; only a newer 1.26.0 should fire.
	if err := st.PutNotified(store.NotifiedState{Ref: ref, Version: "1.25.0"}); err != nil {
		t.Fatal(err)
	}
	in := UpdateInput{Ref: ref, Current: "1.24.3", Latest: "1.26.0", UpdateKind: "minor", Hosts: []string{"home"}}

	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if f.count() != 1 {
		t.Fatalf("publishes = %d, want 1", f.count())
	}
	if got := f.last().body; !strings.Contains(got, "1.24.3 → 1.26.0") {
		t.Errorf("body = %q, want current→newest (1.24.3 → 1.26.0)", got)
	}
	if state, _, _ := st.GetNotified(ref); state.Version != "1.26.0" {
		t.Errorf("stored Version = %q, want 1.26.0", state.Version)
	}
}

func TestDigestRepublishFiresPerNewDigest(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	in := UpdateInput{Ref: "nginx:latest", Current: "latest", RegistryDigest: "sha256:new", RunningDigest: "sha256:old", Hosts: []string{"home"}}
	now := time.Now()

	n.NotifyUpdates(context.Background(), []UpdateInput{in}, now)
	if f.count() != 1 {
		t.Fatalf("publishes = %d, want 1", f.count())
	}
	if got, want := f.last().body, "nginx latest republished on home"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if state, _, _ := st.GetNotified(in.Ref); state.Digest != "sha256:new" {
		t.Errorf("stored Digest = %q, want sha256:new", state.Digest)
	}

	n.NotifyUpdates(context.Background(), []UpdateInput{in}, now)
	if f.count() != 1 {
		t.Errorf("publishes = %d after repeat, want 1", f.count())
	}

	in.RegistryDigest = "sha256:newer"
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, now)
	if f.count() != 2 {
		t.Errorf("publishes = %d after a newer digest, want 2", f.count())
	}
}

func TestDigestNoNotifyWhenRunningIsCurrent(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	// Registry digest equals what the operator already runs: nothing to report.
	in := UpdateInput{Ref: "nginx:latest", Current: "latest", RegistryDigest: "sha256:same", RunningDigest: "sha256:same", Hosts: []string{"home"}}
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if f.count() != 0 {
		t.Errorf("publishes = %d, want 0 (operator already current)", f.count())
	}
	if _, found, _ := st.GetNotified(in.Ref); found {
		t.Error("notified state written though nothing was sent")
	}
}

func TestSemverNewerTagAndRepublishAreIndependent(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	// A republish of the pinned tag with no newer tag: one republish message.
	in := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", RegistryDigest: "sha256:rebuild", RunningDigest: "sha256:old", Hosts: []string{"home"}}
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if f.count() != 1 {
		t.Fatalf("publishes = %d, want 1 (republish only)", f.count())
	}
	if got := f.last().body; !strings.Contains(got, "republished") {
		t.Errorf("body = %q, want a republish message", got)
	}

	// Now a newer tag appears alongside a further republish: two messages.
	in2 := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor", RegistryDigest: "sha256:rebuild2", RunningDigest: "sha256:old", Hosts: []string{"home"}}
	n.NotifyUpdates(context.Background(), []UpdateInput{in2}, time.Now())
	if f.count() != 3 {
		t.Fatalf("publishes = %d, want 3 (one newer-tag + one republish added)", f.count())
	}
	state, _, _ := st.GetNotified(in2.Ref)
	if state.Version != "1.25.0" || state.Digest != "sha256:rebuild2" {
		t.Errorf("stored = %+v, want Version 1.25.0 and Digest sha256:rebuild2", state)
	}

	// Everything is now known: another identical pass is silent.
	n.NotifyUpdates(context.Background(), []UpdateInput{in2}, time.Now())
	if f.count() != 3 {
		t.Errorf("publishes = %d after repeat, want 3", f.count())
	}
}

func TestMultiHostListCapped(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	in := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor",
		Hosts: []string{"e", "a", "c", "b", "d"}}
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if got := f.last().body; !strings.HasSuffix(got, "on a, b, c, +2 more") {
		t.Errorf("body = %q, want host list sorted and capped to 'a, b, c, +2 more'", got)
	}
}

func TestDisabledNotifierIsNoop(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := NewNotifier(f.client(""), st, quietLogger(), "", nil) // no topic

	in := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor", Hosts: []string{"home"}}
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if f.count() != 0 {
		t.Errorf("publishes = %d, want 0 (disabled)", f.count())
	}
	if _, found, _ := st.GetNotified(in.Ref); found {
		t.Error("disabled notifier advanced the notified state")
	}
}

func TestPublishFailureDoesNotAdvanceState(t *testing.T) {
	f := newFakeNtfy(t)
	f.setFail(true)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	in := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor", Hosts: []string{"home"}}
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if f.count() != 1 {
		t.Fatalf("server hits = %d, want 1 (attempted)", f.count())
	}
	if _, found, _ := st.GetNotified(in.Ref); found {
		t.Error("state advanced despite a delivery failure")
	}

	f.setFail(false)
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if f.count() != 2 {
		t.Errorf("server hits = %d, want 2 (retried after recovery)", f.count())
	}
	if state, found, _ := st.GetNotified(in.Ref); !found || state.Version != "1.25.0" {
		t.Errorf("stored = %+v found=%v, want Version 1.25.0 after retry", state, found)
	}
}

func TestAgentDownAfterThreshold(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: false, ConsecutiveFailures: downThreshold - 1}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 0 {
		t.Fatalf("publishes = %d below threshold, want 0", f.count())
	}

	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: false, ConsecutiveFailures: downThreshold}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 1 {
		t.Fatalf("publishes = %d at threshold, want 1", f.count())
	}
	if got := f.last().hdr.Get("Priority"); got != "4" {
		t.Errorf("down Priority = %q, want 4", got)
	}
	if a, _, _ := st.GetAgent("home"); !a.DownNotified {
		t.Error("DownNotified not set after down alert")
	}

	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 1 {
		t.Errorf("publishes = %d while still down, want 1 (no repeat)", f.count())
	}
}

func TestAgentRecoveryFiresOnce(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: true, DownNotified: true}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 1 {
		t.Fatalf("publishes = %d, want 1 (recovery)", f.count())
	}
	if a, _, _ := st.GetAgent("home"); a.DownNotified {
		t.Error("DownNotified not cleared after recovery")
	}

	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 1 {
		t.Errorf("publishes = %d after recovery, want 1 (no repeat)", f.count())
	}
}

func TestWireMismatchOncePerVersion(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)

	// Matching version: no alert.
	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: true, LastWireV: inventory.WireVersion}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 0 {
		t.Fatalf("publishes = %d on matching version, want 0", f.count())
	}

	mismatch := inventory.WireVersion + 1
	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: true, LastWireV: mismatch}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 1 {
		t.Fatalf("publishes = %d on mismatch, want 1", f.count())
	}
	if a, _, _ := st.GetAgent("home"); a.WireNotifiedV != mismatch {
		t.Errorf("WireNotifiedV = %d, want %d", a.WireNotifiedV, mismatch)
	}

	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 1 {
		t.Errorf("publishes = %d for same mismatch, want 1 (no repeat)", f.count())
	}

	// A further-changed version alerts again.
	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: true, LastWireV: mismatch + 1, WireNotifiedV: mismatch}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 2 {
		t.Errorf("publishes = %d after a new mismatch, want 2", f.count())
	}
}

func TestCertReminderWeeklyCadence(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	served := base.Add(30 * 24 * time.Hour)
	staged := base.Add(3650 * 24 * time.Hour) // a fresh re-mint expires far later

	// The served cert is older than the staged bundle: it is not yet installed.
	n := f.notifier(st, "", func(string) (time.Time, bool) { return staged, true })
	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: true, CertNotAfter: served}); err != nil {
		t.Fatal(err)
	}

	n.NotifyAgents(context.Background(), base)
	if f.count() != 1 {
		t.Fatalf("publishes = %d, want 1 (first reminder)", f.count())
	}

	n.NotifyAgents(context.Background(), base.Add(3*24*time.Hour))
	if f.count() != 1 {
		t.Errorf("publishes = %d within a week, want 1 (no nag)", f.count())
	}

	n.NotifyAgents(context.Background(), base.Add(8*24*time.Hour))
	if f.count() != 2 {
		t.Errorf("publishes = %d after a week, want 2 (weekly reminder)", f.count())
	}
}

func TestCertReminderSilentWhenInstalled(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	expiry := time.Now().Add(3650 * 24 * time.Hour)

	// Served cert equals the staged bundle: the operator already installed it.
	n := f.notifier(st, "", func(string) (time.Time, bool) { return expiry, true })
	if err := st.PutAgent(store.AgentStatus{Name: "home", LastOK: true, CertNotAfter: expiry}); err != nil {
		t.Fatal(err)
	}
	n.NotifyAgents(context.Background(), time.Now())
	if f.count() != 0 {
		t.Errorf("publishes = %d when bundle is installed, want 0", f.count())
	}

	// And with no staged bundle at all, nothing fires.
	n2 := f.notifier(st, "", func(string) (time.Time, bool) { return time.Time{}, false })
	n2.NotifyAgents(context.Background(), time.Now())
	if f.count() != 0 {
		t.Errorf("publishes = %d with no staged bundle, want 0", f.count())
	}
}

func TestCertEventMessages(t *testing.T) {
	f := newFakeNtfy(t)
	st := openStore(t)
	n := f.notifier(st, "", nil)
	ctx := context.Background()

	n.NotifyBundleRenewed(ctx, "home")
	if got := f.last().hdr.Get("Tags"); got != "lock" {
		t.Errorf("renewed Tags = %q, want lock", got)
	}

	n.NotifyBundleRemintedSAN(ctx, "home")
	if got := f.last().body; !strings.Contains(got, "address changed") {
		t.Errorf("reminted body = %q, want mention of address change", got)
	}

	n.NotifyCAKeyMissing(ctx, "bundle for agent \"home\"")
	last := f.last()
	if got := last.hdr.Get("Priority"); got != "4" {
		t.Errorf("ca-key Priority = %q, want 4", got)
	}
	if got := last.hdr.Get("Tags"); got != "rotating_light" {
		t.Errorf("ca-key Tags = %q, want rotating_light", got)
	}
	if f.count() != 3 {
		t.Errorf("publishes = %d, want 3", f.count())
	}
}

func TestClickThroughURL(t *testing.T) {
	in := UpdateInput{Ref: "gitea/gitea:1.24.3", Current: "1.24.3", Latest: "1.25.0", UpdateKind: "minor", Hosts: []string{"home"}}

	withDomain := newFakeNtfy(t)
	n := withDomain.notifier(openStore(t), "updates.example.com", nil)
	n.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if got, want := withDomain.last().hdr.Get("Click"), "https://updates.example.com/"; got != want {
		t.Errorf("Click = %q, want %q", got, want)
	}

	noDomain := newFakeNtfy(t)
	n2 := noDomain.notifier(openStore(t), "", nil)
	n2.NotifyUpdates(context.Background(), []UpdateInput{in}, time.Now())
	if got := noDomain.last().hdr.Get("Click"); got != "" {
		t.Errorf("Click = %q, want empty without a domain", got)
	}
}
