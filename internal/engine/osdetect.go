package engine

import (
	"context"
	"net/netip"
	"sync"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/osdetect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
)

// osDetector runs the OS fingerprint probe once per host, the first time an
// open TCP port is reported.
type osDetector struct {
	det  *osdetect.Detector
	mu   sync.Mutex
	done map[netip.Addr]bool
	wg   sync.WaitGroup
}

// newOSDetector returns an OS detector, or nil when OS detection is off.
func newOSDetector(cfg Config) *osDetector {
	if !cfg.OSDetect {
		return nil
	}
	return &osDetector{
		det:  osdetect.New(cfg.OSDetectTimeout),
		done: make(map[netip.Addr]bool),
	}
}

// maybeTrigger starts an OS probe for the result's host if it is the first
// open TCP port seen for that host.
func (o *osDetector) maybeTrigger(ctx context.Context, res Result, out chan<- Result) {
	if o == nil || !res.Open() || res.Proto != ports.TCP {
		return
	}
	addr := res.Addr
	if !addr.IsValid() {
		return
	}

	o.mu.Lock()
	if o.done[addr] {
		o.mu.Unlock()
		return
	}
	o.done[addr] = true
	o.mu.Unlock()

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		osRes, err := o.det.Probe(ctx, addr, res.Port)
		if err != nil {
			return
		}
		select {
		case out <- Result{Host: res.Host, Addr: addr, OS: osRes}:
		case <-ctx.Done():
		}
	}()
}

// wait blocks until every OS probe has finished.
func (o *osDetector) wait() {
	if o != nil {
		o.wg.Wait()
	}
}
