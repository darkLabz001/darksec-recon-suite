package engine

import (
	"context"
	"net/netip"
	"testing"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
)

func TestNewOSDetectorDisabled(t *testing.T) {
	if o := newOSDetector(Config{}); o != nil {
		t.Error("a disabled OS detector was created")
	}
	if o := newOSDetector(Config{OSDetect: true}); o == nil {
		t.Fatal("an enabled OS detector was not created")
	}
}

func TestOSDetectorTriggersOncePerHost(t *testing.T) {
	o := newOSDetector(Config{OSDetect: true})
	addr := netip.MustParseAddr("192.0.2.1")
	res := Result{Addr: addr, Proto: ports.TCP, State: StateOpen, Port: 80}

	o.maybeTrigger(context.Background(), res, make(chan Result, 1))
	o.maybeTrigger(context.Background(), res, make(chan Result, 1))
	o.wait()

	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.done) != 1 {
		t.Errorf("the detector tracked %d hosts, want 1", len(o.done))
	}
}

func TestOSDetectorSkipsNonOpenOrNonTCP(t *testing.T) {
	o := newOSDetector(Config{OSDetect: true})
	addr := netip.MustParseAddr("192.0.2.1")

	o.maybeTrigger(context.Background(), Result{Addr: addr, Proto: ports.UDP, State: StateOpen, Port: 53}, make(chan Result, 1))
	o.maybeTrigger(context.Background(), Result{Addr: addr, Proto: ports.TCP, State: StateClosed, Port: 80}, make(chan Result, 1))
	o.wait()

	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.done) != 0 {
		t.Errorf("the detector tracked %d hosts, want 0", len(o.done))
	}
}
