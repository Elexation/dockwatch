package hub

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/notify"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	startupJitter = 60 * time.Second
	imageJitter   = 250 * time.Millisecond
	renewEvery    = 24 * time.Hour
)

// schedTimer abstracts time.Timer so the loop is drivable without wall-clock waits in tests.
type schedTimer interface {
	C() <-chan time.Time
	Reset(d time.Duration) bool
	Stop() bool
}

type realTimer struct{ t *time.Timer }

func newRealTimer(d time.Duration) schedTimer   { return &realTimer{t: time.NewTimer(d)} }
func (r *realTimer) C() <-chan time.Time        { return r.t.C }
func (r *realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }
func (r *realTimer) Stop() bool                 { return r.t.Stop() }

// Scheduler runs the periodic check cycle, merges manual triggers into the single
// in-flight cycle, and persists per-reference results for the UI to read.
type Scheduler struct {
	poller   *Poller
	reg      RegistryClient
	store    *store.Store
	logger   *slog.Logger
	interval time.Duration

	doorbell chan struct{} // buffered(1); a non-blocking send is a trigger
	force    atomic.Bool   // set by Trigger, swapped false at cycle start
	running  atomic.Bool   // drives the web UI's checking state
	lastDone atomic.Int64  // unixnano of the last completed cycle; 0 = none yet

	renew    func()           // opaque cert-renewal closure; keeps this package off pki
	notifier *notify.Notifier // nil for a hub built without notifications

	cycle     func(ctx context.Context, force bool)
	newTimer  func(d time.Duration) schedTimer
	startup   func() time.Duration
	imgJitter func() time.Duration
	sleep     func(ctx context.Context, d time.Duration)
}

// NewScheduler wires the cycle dependencies; renew may be nil for a local-only
// hub and notifier may be nil when notifications are disabled.
func NewScheduler(p *Poller, reg RegistryClient, st *store.Store, logger *slog.Logger, interval time.Duration, renew func(), notifier *notify.Notifier) *Scheduler {
	s := &Scheduler{
		poller:   p,
		reg:      reg,
		store:    st,
		logger:   logger,
		interval: interval,
		doorbell: make(chan struct{}, 1),
		renew:    renew,
		notifier: notifier,
	}
	s.cycle = s.runCycle
	s.newTimer = newRealTimer
	s.startup = func() time.Duration { return jitter(startupJitter) }
	s.imgJitter = func() time.Duration { return jitter(imageJitter) }
	s.sleep = sleepCtx
	return s
}

// jitter returns a uniform random duration in [0, max).
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max)))
}

func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Trigger requests an out-of-band cycle; force is set before the ring so a cycle already draining the doorbell still sees it.
func (s *Scheduler) Trigger() {
	s.force.Store(true)
	select {
	case s.doorbell <- struct{}{}:
	default:
	}
}

// Running reports whether a check cycle is in flight.
func (s *Scheduler) Running() bool { return s.running.Load() }

// LastCycle returns when the most recent cycle completed, zero before the
// first. It advances even when a cycle persisted nothing, so a waiter can
// always detect completion.
func (s *Scheduler) LastCycle() time.Time {
	n := s.lastDone.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Run blocks until ctx is cancelled, firing a cycle on the interval timer or a trigger.
func (s *Scheduler) Run(ctx context.Context) {
	if s.renew != nil {
		go s.runRenewals(ctx)
	}
	timer := s.newTimer(s.startup()) // first fire after a startup jitter, not a full interval
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C():
			s.fire(ctx)
			s.afterCycle(timer)
		case <-s.doorbell:
			s.fire(ctx)
			s.afterCycle(timer)
		}
	}
}

func (s *Scheduler) fire(ctx context.Context) {
	s.running.Store(true)
	s.cycle(ctx, s.force.Swap(false))
	s.running.Store(false)
	s.lastDone.Store(time.Now().UnixNano())
}

// afterCycle absorbs a trigger that landed during the cycle (no second run) and reschedules the next automatic cycle.
func (s *Scheduler) afterCycle(timer schedTimer) {
	select {
	case <-s.doorbell:
	default:
	}
	if !timer.Stop() { // drain a tick that fired mid-cycle; the wake-on-timer branch leaves C empty, so default falls through
		select {
		case <-timer.C():
		default:
		}
	}
	timer.Reset(s.interval)
}

// runRenewals re-runs the injected cert-renewal pass daily; the startup pass runs before Run.
func (s *Scheduler) runRenewals(ctx context.Context) {
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.renew()
		}
	}
}

func (s *Scheduler) runCycle(ctx context.Context, force bool) {
	now := time.Now()
	refs := s.dedup(s.poller.Gather(ctx, now))

	var inputs []notify.UpdateInput
	cooled := make(map[string]bool) // registries that returned 429 this cycle
	first := true
	for ref, agg := range refs {
		if ctx.Err() != nil {
			return // shutdown mid-cycle intentionally skips notifying
		}
		if agg.kind == KindLocal { // not checkable: persist a marker, no registry call
			tag, _ := tagOf(ref)
			s.put(store.CheckResult{Ref: ref, Kind: KindLocal.String(), Status: store.StatusOK, Current: tag, CheckedAt: now})
			continue
		}

		prev, found, _ := s.store.GetCheck(ref)
		if !ShouldCheck(prev, found, now, s.interval, force, agg.tagFilter) {
			continue // fresh cache: left intact even if its registry is cooled below
		}

		host := registryOf(ref)
		if cooled[host] {
			s.put(store.CheckResult{Ref: ref, Kind: agg.kind.String(), Status: store.StatusRateLimited, CheckedAt: now})
			continue
		}

		if !first {
			s.sleep(ctx, s.imgJitter()) // anti-burst delay, only between real registry calls
		}
		first = false

		res := Check(ctx, s.reg, ref, agg.tagFilter, now)
		if res.Status == store.StatusRateLimited {
			cooled[host] = true
		}
		s.put(res)

		if res.Status == store.StatusOK {
			current := res.Current // SEMVER records the running tag; DIGEST does not
			if agg.kind == KindDigest {
				current, _ = tagOf(ref)
			}
			inputs = append(inputs, notify.UpdateInput{
				Ref:            ref,
				Current:        current,
				Latest:         res.Latest,
				UpdateKind:     res.UpdateKind,
				RegistryDigest: res.RegistryDigest,
				RunningDigest:  agg.runningDigest,
				Hosts:          agg.hosts,
			})
		}
	}

	if s.notifier != nil {
		s.notifier.NotifyUpdates(ctx, inputs, now)
		s.notifier.NotifyAgents(ctx, now)
	}
}

// refAgg collects, per image reference, the facts the notifier joins across all
// hosts running it.
type refAgg struct {
	kind          Kind
	runningDigest string
	hosts         []string
	tagFilter     string // dw.tags label; smallest non-empty value wins on conflict
}

// dedup collapses running, watched containers to unique image refs, accumulating
// the hosts, a running digest, and the dw.tags filter per ref; a checkable
// classification beats LOCAL when a ref appears as both.
func (s *Scheduler) dedup(invs []inventory.Inventory) map[string]*refAgg {
	out := make(map[string]*refAgg)
	for _, inv := range invs {
		for _, c := range inv.Containers {
			if c.State != "running" || c.Labels["dw.watch"] == "false" {
				continue
			}
			agg, ok := out[c.Image]
			if !ok {
				agg = &refAgg{kind: Classify(c)}
				out[c.Image] = agg
			} else if agg.kind == KindLocal {
				agg.kind = Classify(c)
			}
			if inv.Host != "" {
				agg.hosts = appendUnique(agg.hosts, inv.Host)
			}
			if agg.runningDigest == "" {
				agg.runningDigest = runningDigest(c, c.Image)
			}
			if f := c.Labels["dw.tags"]; f != "" && f != agg.tagFilter {
				if agg.tagFilter == "" {
					agg.tagFilter = f
				} else {
					if f < agg.tagFilter {
						agg.tagFilter = f
					}
					s.logger.Warn("conflicting dw.tags labels for image", "ref", c.Image, "using", agg.tagFilter)
				}
			}
		}
	}
	return out
}

// runningDigest returns the index digest the container runs for ref: the sha256
// from the repo_digests entry whose repository matches ref, else the first
// entry. Docker records repo_digests at the index level, so this is the value
// comparable to the registry's top-level digest.
func runningDigest(c inventory.Container, ref string) string {
	want := bareRepo(ref)
	first := ""
	for _, rd := range c.RepoDigests {
		at := strings.IndexByte(rd, '@')
		if at < 0 {
			continue
		}
		repo, dig := rd[:at], rd[at+1:]
		if first == "" {
			first = dig
		}
		if bareRepo(repo) == want {
			return dig
		}
	}
	return first
}

// bareRepo reduces a reference or repo_digest entry to its repository path,
// dropping any registry host, tag, and digest so two spellings of the same image
// compare equal.
func bareRepo(s string) string {
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		if j := strings.IndexByte(s[i+1:], ':'); j >= 0 {
			s = s[:i+1+j]
		}
	} else if j := strings.IndexByte(s, ':'); j >= 0 {
		s = s[:j]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		if host := s[:i]; strings.ContainsAny(host, ".:") || host == "localhost" {
			s = s[i+1:]
		}
	}
	return s
}

func appendUnique(ss []string, v string) []string {
	for _, s := range ss {
		if s == v {
			return ss
		}
	}
	return append(ss, v)
}

// registryOf returns ref's registry host for the per-cycle 429 cooldown; "" if unparseable.
func registryOf(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return ""
	}
	return r.Context().RegistryStr()
}

func (s *Scheduler) put(r store.CheckResult) {
	if err := s.store.PutCheck(r); err != nil {
		s.logger.Warn("persist check", "ref", r.Ref, "err", err)
	}
}
