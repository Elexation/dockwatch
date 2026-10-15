package httpd

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGuardBackoffDoublesThenCaps(t *testing.T) {
	now := time.Unix(0, 0)
	g := newAuthGuard(func() time.Time { return now })

	for i := 0; i < freeFailures; i++ {
		g.failed()
	}
	if err := g.throttled(); err != nil {
		t.Fatalf("blocked within the free failures: %v", err)
	}

	for _, want := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		g.failed()
		var te throttledError
		if !errors.As(g.throttled(), &te) || te.Wait != want*time.Second {
			t.Fatalf("after failure %d: got %v, want block of %v", g.fails, te.Wait, want*time.Second)
		}
		now = now.Add(te.Wait)
		if err := g.throttled(); err != nil {
			t.Fatalf("still blocked once the window passed: %v", err)
		}
	}

	g.succeeded()
	g.failed()
	if err := g.throttled(); err != nil {
		t.Errorf("success did not reset the count: %v", err)
	}
}

func TestGuardBusyWhenSlotsFull(t *testing.T) {
	g := newAuthGuard(time.Now)
	g.wait = 10 * time.Millisecond
	for i := 0; i < hashSlots; i++ {
		if err := g.acquire(context.Background()); err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
	}
	if _, err := g.hash(context.Background(), "hunter2pass"); !errors.Is(err, errBusy) {
		t.Fatalf("hash with every slot taken: err=%v, want errBusy", err)
	}
	g.release()
	if _, err := g.hash(context.Background(), "hunter2pass"); err != nil {
		t.Errorf("hash after a slot freed: %v", err)
	}
}
