package ratelimit

import (
	"context"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock used to drive the limiter.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestNewDisablesLimitingForNonPositiveRates(t *testing.T) {
	for _, rate := range []float64{0, -1} {
		l := New(rate)
		if l.rate != 0 {
			t.Errorf("the rate is %v, want 0", l.rate)
		}
		if err := l.Wait(context.Background()); err != nil {
			t.Errorf("Wait returned an error: %v", err)
		}
	}
}

func TestNilLimiterIsUsable(t *testing.T) {
	var l *Limiter
	if err := l.Wait(context.Background()); err != nil {
		t.Errorf("Wait returned an error: %v", err)
	}
}

func TestBurstIsAvailableImmediately(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	l := New(100)
	l.now = clock.Now

	// The bucket starts with a burst of rate/10 tokens, all available
	// without waiting.
	start := clock.Now()
	for i := 0; i < 10; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("Wait returned an error: %v", err)
		}
	}
	if elapsed := clock.Now().Sub(start); elapsed != 0 {
		t.Errorf("the burst took %v, want no time at all", elapsed)
	}
}

func TestReserveWaitsForTheNextToken(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	l := New(100)
	l.now = clock.Now

	// Drain the burst.
	for i := 0; i < 10; i++ {
		if _, ok := l.reserve(); !ok {
			t.Fatalf("reserve %d was refused", i)
		}
	}

	delay, ok := l.reserve()
	if ok {
		t.Fatal("reserve handed out a token that should not be available")
	}
	if delay <= 0 {
		t.Errorf("the delay is %v, want a positive duration", delay)
	}
	// At 100 per second a token becomes available every 10ms.
	if delay > 20*time.Millisecond {
		t.Errorf("the delay is %v, want at most 20ms", delay)
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	l := New(100)
	l.now = clock.Now

	if _, ok := l.reserve(); !ok {
		t.Fatal("the first reserve was refused")
	}

	// One second at a hundred tokens per second refills the bucket to
	// its burst size of ten tokens.
	clock.Advance(time.Second)
	for i := 0; i < 10; i++ {
		if _, ok := l.reserve(); !ok {
			t.Fatalf("reserve %d was refused after the refill", i)
		}
	}
}

func TestTokenCountIsCappedAtTheBurstSize(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	l := New(10)
	l.now = clock.Now

	clock.Advance(time.Hour)
	if _, ok := l.reserve(); !ok {
		t.Fatal("the first reserve was refused")
	}
	if l.tokens > l.burst {
		t.Errorf("the bucket holds %v tokens, want at most %v", l.tokens, l.burst)
	}
}

func TestWaitBlocksUntilTheContextIsCancelled(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	l := New(1)
	l.now = clock.Now

	// Drain the single token.
	if _, ok := l.reserve(); !ok {
		t.Fatal("the first reserve was refused")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() { done <- l.Wait(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Wait returned no error after the context was cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after the context was cancelled")
	}
}

func TestWaitPacesRealTime(t *testing.T) {
	l := New(50)
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 15; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait returned an error: %v", err)
		}
	}
	elapsed := time.Since(start)

	// The burst absorbs the first five requests, the remaining ten are
	// paced at 50 per second, which is 200ms.
	if elapsed < 150*time.Millisecond {
		t.Errorf("fifteen probes took %v, want at least 150ms", elapsed)
	}
}

func TestWaitIsSafeForConcurrentUse(t *testing.T) {
	l := New(1000)
	ctx := context.Background()

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				if err := l.Wait(ctx); err != nil {
					t.Errorf("Wait returned an error: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
