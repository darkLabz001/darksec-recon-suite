// Package ratelimit implements a token bucket rate limiter suitable for
// pacing network probes.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token bucket. It is safe for concurrent use.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// New returns a limiter permitting approximately rate events per second.
// A burst of rate/10 (minimum 1) is allowed to absorb momentary spikes.
// A rate of zero or less disables limiting entirely.
func New(rate float64) *Limiter {
	if rate <= 0 {
		return &Limiter{rate: 0}
	}
	burst := rate / 10
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		now:    time.Now,
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.rate <= 0 {
		return ctx.Err()
	}
	for {
		delay, ok := l.reserve()
		if ok {
			return nil
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// reserve consumes one token if available, returning the wait duration
// needed before the next attempt otherwise.
func (l *Limiter) reserve() (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if l.last.IsZero() {
		l.last = now
	}
	elapsed := now.Sub(l.last)
	if elapsed > 0 {
		l.tokens += elapsed.Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.last = now

	if l.tokens >= 1 {
		l.tokens--
		return 0, true
	}
	need := (1 - l.tokens) / l.rate
	if need <= 0 {
		need = 1e-6
	}
	return time.Duration(need * float64(time.Second)), false
}
