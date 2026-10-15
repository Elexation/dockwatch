package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/elexation/dockwatch/internal/auth"
)

const (
	hashSlots    = 2               // argon2id takes 64 MiB per run; this bounds the peak
	hashWait     = 5 * time.Second // queue time for a slot before a busy 503
	freeFailures = 5               // wrong passwords allowed before backoff starts
	maxBackoff   = time.Minute
)

// errBusy means no hashing slot freed up in time.
var errBusy = errors.New("password check busy")

const busyBanner = "The hub is busy, try again in a moment"

// throttledError means recent wrong passwords have blocked attempts for Wait.
type throttledError struct{ Wait time.Duration }

func (e throttledError) Error() string { return "password attempts throttled" }

// authGuard bounds concurrent argon2id work and slows password guessing. Both
// limits are global: behind a proxy every client shares one address, and the
// hub has a single admin anyway.
type authGuard struct {
	slots chan struct{}
	wait  time.Duration
	now   func() time.Time

	mu      sync.Mutex
	fails   int
	blocked time.Time // attempts are refused until then
}

func newAuthGuard(now func() time.Time) *authGuard {
	return &authGuard{slots: make(chan struct{}, hashSlots), wait: hashWait, now: now}
}

// verify checks pw against encoded inside a slot. The block is checked again
// after queueing, so requests queued during a flood cannot slip past it.
func (g *authGuard) verify(ctx context.Context, encoded, pw string) (bool, error) {
	if err := g.throttled(); err != nil {
		return false, err
	}
	if err := g.acquire(ctx); err != nil {
		return false, err
	}
	defer g.release()
	if err := g.throttled(); err != nil {
		return false, err
	}
	return auth.Verify(encoded, pw)
}

// hash runs auth.Hash inside a slot; creating a password is never throttled.
func (g *authGuard) hash(ctx context.Context, pw string) (string, error) {
	if err := g.acquire(ctx); err != nil {
		return "", err
	}
	defer g.release()
	return auth.Hash(pw)
}

// failed records a wrong password; past freeFailures each one doubles the block.
func (g *authGuard) failed() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fails++
	if over := g.fails - freeFailures; over > 0 {
		g.blocked = g.now().Add(min(time.Second<<min(over-1, 6), maxBackoff))
	}
}

// succeeded clears the count after a correct password.
func (g *authGuard) succeeded() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fails = 0
	g.blocked = time.Time{}
}

func (g *authGuard) throttled() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if wait := g.blocked.Sub(g.now()); wait > 0 {
		return throttledError{Wait: wait}
	}
	return nil
}

// acquire takes a slot. A client that hangs up also reads as busy, never as
// a wrong password.
func (g *authGuard) acquire(ctx context.Context) error {
	t := time.NewTimer(g.wait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-t.C:
		return errBusy
	case <-ctx.Done():
		return errBusy
	}
}

func (g *authGuard) release() { <-g.slots }

// refusal maps a guard error to a status and banner and sets Retry-After;
// 0 if err is neither busy nor throttled.
func refusal(w http.ResponseWriter, err error) (int, string) {
	var t throttledError
	switch {
	case errors.Is(err, errBusy):
		w.Header().Set("Retry-After", strconv.Itoa(int(hashWait/time.Second)))
		return http.StatusServiceUnavailable, busyBanner
	case errors.As(err, &t):
		secs := int((t.Wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		return http.StatusTooManyRequests, fmt.Sprintf("Too many failed attempts, wait %ds and try again", secs)
	}
	return 0, ""
}

// refusalCode names a guard refusal for the settings redirect; "" if err is neither busy nor throttled.
func refusalCode(err error) string {
	var t throttledError
	switch {
	case errors.Is(err, errBusy):
		return "busy"
	case errors.As(err, &t):
		return "throttled"
	}
	return ""
}
