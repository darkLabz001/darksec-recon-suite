package engine

import (
	"context"
	"sync"
	"time"
)

// gate is a dynamically resizable counting semaphore.
//
// Unlike a buffered channel it can change its limit while permits are
// outstanding, which is what makes the adaptive concurrency controller
// possible.
type gate struct {
	mu     sync.Mutex
	cond   *sync.Cond
	limit  int
	active int
}

func newGate(limit int) *gate {
	if limit < 1 {
		limit = 1
	}
	g := &gate{limit: limit}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// acquire blocks until a permit is available or ctx is cancelled.
func (g *gate) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	g.mu.Lock()
	for g.active >= g.limit {
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			return err
		}
		// A sync.Cond cannot observe a context, so a cancellation
		// callback broadcasts to every waiter. The callback is
		// unregistered as soon as the permit arrives.
		stop := context.AfterFunc(ctx, func() {
			g.mu.Lock()
			g.cond.Broadcast()
			g.mu.Unlock()
		})
		g.cond.Wait()
		stop()
	}
	g.active++
	g.mu.Unlock()
	return nil
}

// release returns a permit to the pool.
func (g *gate) release() {
	g.mu.Lock()
	g.active--
	if g.active < 0 {
		g.active = 0
	}
	g.cond.Signal()
	g.mu.Unlock()
}

// setLimit resizes the gate and wakes any waiters.
func (g *gate) setLimit(n int) {
	if n < 1 {
		n = 1
	}
	g.mu.Lock()
	g.limit = n
	g.cond.Broadcast()
	g.mu.Unlock()
}

// current returns the active and limit values.
func (g *gate) current() (active, limit int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active, g.limit
}

// controller implements an AIMD (additive increase, multiplicative
// decrease) concurrency controller inspired by TCP congestion control.
//
// Sustained failures cause the in-flight window to shrink quickly, which
// keeps a scan from overwhelming a target that is silently dropping
// packets. A healthy target causes the window to grow gradually, which
// finds the highest sustainable concurrency without overshooting.
type controller struct {
	mu sync.Mutex

	min     int
	max     int
	limit   int
	window  int
	samples int
	errs    int
	oks     int
	rttSum  time.Duration
	rttMax  time.Duration
	ewmaRTT time.Duration
	ewmaSet bool
}

const (
	// controllerWindow is the number of samples considered per adjustment.
	controllerWindow = 64
	// decreaseFactor is applied to the limit when errors dominate.
	decreaseFactor = 0.75
	// errorCeiling is the error ratio above which the window shrinks.
	errorCeiling = 0.20
	// errorFloor is the error ratio below which the window may grow.
	errorFloor = 0.05
	// healthyRTT is the round trip time below which growth is allowed.
	healthyRTT = 750 * time.Millisecond
)

func newController(min, max int) *controller {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	return &controller{min: min, max: max, limit: min}
}

// observe records the outcome of a probe.
func (c *controller) observe(rtt time.Duration, failed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.samples++
	if failed {
		c.errs++
	} else {
		c.oks++
	}
	if rtt > 0 {
		c.rttSum += rtt
		if rtt > c.rttMax {
			c.rttMax = rtt
		}
		if !c.ewmaSet {
			c.ewmaRTT = rtt
			c.ewmaSet = true
		} else {
			// Exponential moving average with alpha = 1/8.
			c.ewmaRTT = (7*c.ewmaRTT + rtt) / 8
		}
	}

	if c.samples < controllerWindow {
		return
	}

	total := c.errs + c.oks
	errRatio := float64(c.errs) / float64(total)
	switch {
	case errRatio > errorCeiling:
		next := int(float64(c.limit) * decreaseFactor)
		if next < c.min {
			next = c.min
		}
		c.limit = next
	case errRatio < errorFloor && c.ewmaRTT < healthyRTT:
		step := c.limit / 10
		if step < 1 {
			step = 1
		}
		next := c.limit + step
		if next > c.max {
			next = c.max
		}
		c.limit = next
	}

	c.samples = 0
	c.errs = 0
	c.oks = 0
	c.rttSum = 0
	c.rttMax = 0
}

// currentLimit returns the current concurrency limit.
func (c *controller) currentLimit() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limit
}

// stats returns a snapshot of the controller state.
func (c *controller) stats() (limit int, ewma time.Duration, maxRTT time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limit, c.ewmaRTT, c.rttMax
}
