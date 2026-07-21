package hub

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/registry"
	"github.com/elexation/dockwatch/internal/store"
)

// fakeTimer hands ticks to the loop on demand and reports each Reset over a channel for race-free assertions.
type fakeTimer struct {
	c     chan time.Time
	reset chan time.Duration
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{c: make(chan time.Time, 1), reset: make(chan time.Duration, 8)}
}

func (f *fakeTimer) C() <-chan time.Time        { return f.c }
func (f *fakeTimer) Reset(d time.Duration) bool { f.reset <- d; return true }
func (f *fakeTimer) Stop() bool                 { return true }
func (f *fakeTimer) fire()                      { f.c <- time.Unix(0, 0) }

// fixedLocal is a localReader yielding a preset container set.
type fixedLocal struct{ containers []inventory.Container }

func (f fixedLocal) Read(context.Context) (inventory.Inventory, error) {
	return inventory.Inventory{V: inventory.WireVersion, Host: "local", Docker: inventory.DockerOK, Containers: f.containers}, nil
}

func TestMergeGate(t *testing.T) {
	st := openStore(t)
	p := NewPoller(emptyLocal{}, nil, nil, st, quietLogger())
	s := NewScheduler(p, &fakeReg{}, st, quietLogger(), time.Hour, nil, nil)
	s.startup = func() time.Duration { return 0 }
	ft := newFakeTimer()
	s.newTimer = func(time.Duration) schedTimer { return ft }

	started := make(chan struct{})
	release := make(chan struct{})
	var count atomic.Int32
	s.cycle = func(context.Context, bool) {
		count.Add(1)
		started <- struct{}{}
		<-release
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	ft.fire()
	<-started   // cycle is now running and blocked
	s.Trigger() // two triggers during the run...
	s.Trigger() // ...must collapse to zero additional cycles
	close(release)
	<-ft.reset // afterCycle finished (doorbell drained, timer reset)

	if got := count.Load(); got != 1 {
		t.Errorf("cycle ran %d times, want 1 (triggers merged)", got)
	}
}

func TestRunningAndLastCycle(t *testing.T) {
	st := openStore(t)
	p := NewPoller(emptyLocal{}, nil, nil, st, quietLogger())
	s := NewScheduler(p, &fakeReg{}, st, quietLogger(), time.Hour, nil, nil)
	s.startup = func() time.Duration { return 0 }
	ft := newFakeTimer()
	s.newTimer = func(time.Duration) schedTimer { return ft }

	if s.Running() || !s.LastCycle().IsZero() {
		t.Fatal("fresh scheduler must be idle with a zero LastCycle")
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var sawRunning atomic.Bool
	s.cycle = func(context.Context, bool) {
		sawRunning.Store(s.Running())
		started <- struct{}{}
		<-release
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	before := time.Now()
	s.Trigger()
	<-started // cycle is in flight and blocked
	if !s.Running() {
		t.Error("Running() = false during a cycle")
	}
	close(release)
	<-ft.reset // afterCycle finished, so fire() has stamped completion

	if !sawRunning.Load() {
		t.Error("running flag was not set before the cycle body ran")
	}
	if s.Running() {
		t.Error("Running() = true after the cycle completed")
	}
	if last := s.LastCycle(); last.Before(before) {
		t.Errorf("LastCycle = %v, want at or after %v", last, before)
	}
}

func TestTimerReset(t *testing.T) {
	st := openStore(t)
	p := NewPoller(emptyLocal{}, nil, nil, st, quietLogger())
	s := NewScheduler(p, &fakeReg{}, st, quietLogger(), 42*time.Minute, nil, nil)
	s.startup = func() time.Duration { return 0 }
	s.cycle = func(context.Context, bool) {}
	ft := newFakeTimer()
	s.newTimer = func(time.Duration) schedTimer { return ft }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	ft.fire() // timer branch
	if got := <-ft.reset; got != s.interval {
		t.Errorf("reset after timer = %v, want %v", got, s.interval)
	}
	s.Trigger() // doorbell branch
	if got := <-ft.reset; got != s.interval {
		t.Errorf("reset after trigger = %v, want %v", got, s.interval)
	}
}

func TestRunCycleFilter(t *testing.T) {
	const semverRef = "gitea/gitea:1.24.3"
	giteaRepo, _ := repoOf(semverRef)
	reg := &fakeReg{
		tags:    map[string][]string{giteaRepo: {"1.24.3", "1.25.0"}},
		digests: map[string]string{semverRef: "sha256:idx"},
	}
	local := fixedLocal{containers: []inventory.Container{
		{Image: semverRef, State: "running", RepoDigests: []string{"repo@sha256:local"}},
		{Image: "redis:7", State: "running", RepoDigests: []string{"repo@sha256:local"}, Labels: map[string]string{"dw.watch": "false"}},
		{Image: "nginx:1.25", State: "exited", RepoDigests: []string{"repo@sha256:local"}},
		{Image: "myapp:1.0", State: "running"}, // no repo digests => LOCAL
	}}

	st := openStore(t)
	s := newPipelineScheduler(t, local, reg, st)
	s.runCycle(context.Background(), false)

	got, found, err := st.GetCheck(semverRef)
	if err != nil || !found {
		t.Fatalf("semver ref: found=%v err=%v", found, err)
	}
	if got.Kind != KindSemver.String() || got.Status != store.StatusOK || got.Latest != "1.25.0" || got.UpdateKind != "minor" {
		t.Errorf("semver result = %+v", got)
	}

	loc, found, _ := st.GetCheck("myapp:1.0")
	if !found || loc.Kind != KindLocal.String() || loc.Status != store.StatusOK {
		t.Errorf("local result = %+v found=%v", loc, found)
	}
	if reg.listN != 1 || reg.digN != 1 {
		t.Errorf("registry calls = (list %d, digest %d), want (1,1): only the semver ref is checkable", reg.listN, reg.digN)
	}

	for _, ref := range []string{"redis:7", "nginx:1.25"} {
		if _, found, _ := st.GetCheck(ref); found {
			t.Errorf("%s was persisted; want filtered out", ref)
		}
	}
}

func TestRunCycleForceBypassesCache(t *testing.T) {
	const ref = "gitea/gitea:1.24.3"
	repo, _ := repoOf(ref)
	reg := &fakeReg{tags: map[string][]string{repo: {"1.24.3"}}, digests: map[string]string{ref: "sha256:idx"}}
	local := fixedLocal{containers: []inventory.Container{{Image: ref, State: "running", RepoDigests: []string{"repo@sha256:local"}}}}

	st := openStore(t)
	if err := st.PutCheck(store.CheckResult{Ref: ref, Status: store.StatusOK, CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s := newPipelineScheduler(t, local, reg, st)

	s.runCycle(context.Background(), false)
	if reg.listN != 0 {
		t.Errorf("fresh ref rechecked without force (listN=%d)", reg.listN)
	}
	s.runCycle(context.Background(), true)
	if reg.listN != 1 {
		t.Errorf("force did not bypass the cache (listN=%d, want 1)", reg.listN)
	}
}

func TestRunCycleRateLimitCooldown(t *testing.T) {
	reg := &fakeReg{digErr: registry.ErrRateLimited}
	local := fixedLocal{containers: []inventory.Container{
		{Image: "nginx:latest", State: "running", RepoDigests: []string{"repo@sha256:local"}},
		{Image: "redis:latest", State: "running", RepoDigests: []string{"repo@sha256:local"}},
	}}

	st := openStore(t)
	s := newPipelineScheduler(t, local, reg, st)
	s.runCycle(context.Background(), false)

	if reg.digN != 1 {
		t.Errorf("registry hit %d times, want 1 (cooldown skips the rest of the registry)", reg.digN)
	}
	for _, ref := range []string{"nginx:latest", "redis:latest"} {
		r, found, _ := st.GetCheck(ref)
		if !found || r.Status != store.StatusRateLimited {
			t.Errorf("%s status = %q found=%v, want rate-limited", ref, r.Status, found)
		}
	}
}

func TestRunCycleTagFilterFromLabel(t *testing.T) {
	const ref = "gitea/gitea:1.24.3"
	repo, _ := repoOf(ref)
	reg := &fakeReg{
		// 2024.11.2 shares the scheme; only the label's filter excludes it.
		tags:    map[string][]string{repo: {"1.24.3", "1.25.0", "2024.11.2"}},
		digests: map[string]string{ref: "sha256:idx"},
	}
	local := fixedLocal{containers: []inventory.Container{
		{Image: ref, State: "running", RepoDigests: []string{"repo@sha256:local"},
			Labels: map[string]string{"dw.tags": `1\.\d+\.\d+`}},
	}}

	st := openStore(t)
	s := newPipelineScheduler(t, local, reg, st)
	s.runCycle(context.Background(), false)

	got, found, _ := st.GetCheck(ref)
	if !found || got.Latest != "1.25.0" || got.TagFilter != `1\.\d+\.\d+` {
		t.Errorf("filtered check = %+v found=%v, want latest 1.25.0 with the filter recorded", got, found)
	}
}

func TestDedupTagFilterConflict(t *testing.T) {
	st := openStore(t)
	s := newPipelineScheduler(t, emptyLocal{}, &fakeReg{}, st)
	mk := func(filter string) inventory.Container {
		c := inventory.Container{Image: "app:1.0.0", State: "running", RepoDigests: []string{"repo@sha256:x"}}
		if filter != "" {
			c.Labels = map[string]string{"dw.tags": filter}
		}
		return c
	}
	refs := s.dedup([]inventory.Inventory{{Host: "a", Containers: []inventory.Container{
		mk("zzz"), mk("aaa"), mk(""),
	}}})
	if got := refs["app:1.0.0"].tagFilter; got != "aaa" {
		t.Errorf("tagFilter = %q, want the lexicographically smallest non-empty (aaa)", got)
	}
}

// newPipelineScheduler builds a scheduler whose runCycle can be called directly with deterministic (zero) jitter.
func newPipelineScheduler(t *testing.T, local localReader, reg RegistryClient, st *store.Store) *Scheduler {
	t.Helper()
	p := NewPoller(local, nil, nil, st, quietLogger())
	s := NewScheduler(p, reg, st, quietLogger(), time.Hour, nil, nil)
	s.imgJitter = func() time.Duration { return 0 }
	s.sleep = func(context.Context, time.Duration) {}
	return s
}
