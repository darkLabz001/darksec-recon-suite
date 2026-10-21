package engine

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ratelimit"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

// Order controls the sequence in which probes are issued.
type Order int

const (
	// OrderHost issues every port of a host before moving to the next host.
	OrderHost Order = iota
	// OrderPort issues one port across every host before moving on. It
	// spreads the load evenly when many hosts are scanned.
	OrderPort
	// OrderAuto picks the ordering that suits the number of hosts.
	OrderAuto
)

// Config configures a scan.
type Config struct {
	// Timeout is the per probe connection timeout.
	Timeout time.Duration
	// Concurrency overrides the adaptive concurrency controller.
	Concurrency int
	// MinConcurrency is the lower bound used by the controller.
	MinConcurrency int
	// MaxConcurrency is the upper bound used by the controller.
	MaxConcurrency int
	// Rate limits the number of probes per second. Zero means unlimited.
	Rate float64
	// SourceAddr binds the scanner to a specific local address.
	SourceAddr netip.Addr
	// Detect enables service detection on open ports.
	Detect bool
	// DetectTimeout bounds a single protocol exchange.
	DetectTimeout time.Duration
	// UserAgent is sent with HTTP requests.
	UserAgent string
	// EnableJA3 turns on TLS handshake fingerprinting.
	EnableJA3 bool
	// EnableHTTP allows HTTP probing to run.
	EnableHTTP bool
	// EnableFavicon allows favicon hash collection.
	EnableFavicon bool
	// HostHeader overrides the Host header used for HTTP requests.
	HostHeader string
	// Protocols restricts detection to the named protocols.
	Protocols []string
	// Fallbacks are the protocols tried on ports with no known mapping.
	Fallbacks []string
	// Rules are additional fingerprint rules.
	Rules []detect.Rule
	// Order controls the probe sequence.
	Order Order
	// HappyDelay is the delay before the second address of a dual stack
	// host is attempted.
	HappyDelay time.Duration
	// Interface selects the network interface used by the SYN engine.
	Interface string
}

// Defaults for the scan configuration.
const (
	DefaultTimeout        = time.Second
	DefaultDetectTimeout  = 5 * time.Second
	DefaultMinConcurrency = 64
	DefaultMaxConcurrency = 4000
	DefaultHappyDelay     = 250 * time.Millisecond
)

// probeJob is a single unit of work.
type probeJob struct {
	host target.Host
	port uint16
}

// scanner holds the shared machinery of every scan engine.
type scanner struct {
	cfg     Config
	gate    *gate
	ctrl    *controller
	limiter *ratelimit.Limiter
	det     *detect.Detector
	dialer  net.Dialer
}

// newScanner prepares the shared scanner machinery.
func newScanner(cfg Config) *scanner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MinConcurrency <= 0 {
		cfg.MinConcurrency = DefaultMinConcurrency
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = DefaultMaxConcurrency
	}
	if cfg.MaxConcurrency < cfg.MinConcurrency {
		cfg.MaxConcurrency = cfg.MinConcurrency
	}
	if cfg.HappyDelay <= 0 {
		cfg.HappyDelay = DefaultHappyDelay
	}
	if cfg.DetectTimeout <= 0 {
		cfg.DetectTimeout = DefaultDetectTimeout
	}

	limit := cfg.MinConcurrency
	if cfg.Concurrency > 0 {
		limit = cfg.Concurrency
		if limit > cfg.MaxConcurrency {
			limit = cfg.MaxConcurrency
		}
		cfg.Concurrency = 0
	}

	s := &scanner{
		cfg:  cfg,
		gate: newGate(limit),
		ctrl: newController(cfg.MinConcurrency, cfg.MaxConcurrency),
	}
	if cfg.Rate > 0 {
		s.limiter = ratelimit.New(cfg.Rate)
	}
	if cfg.Detect {
		s.det = detect.New(detect.Config{
			Timeout:       cfg.DetectTimeout,
			UserAgent:     cfg.UserAgent,
			EnableJA3:     cfg.EnableJA3,
			EnableHTTP:    cfg.EnableHTTP,
			EnableFavicon: cfg.EnableFavicon,
			HostHeader:    cfg.HostHeader,
			Protocols:     cfg.Protocols,
			Fallbacks:     cfg.Fallbacks,
			Rules:         cfg.Rules,
		})
	}

	s.dialer = net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: -1,
	}
	if cfg.SourceAddr.IsValid() {
		s.dialer.LocalAddr = &net.TCPAddr{IP: cfg.SourceAddr.AsSlice()}
	}
	return s
}

// prober performs a single probe and reports the result.
type prober func(ctx context.Context, s *scanner, job probeJob) Result

// run drives the scan pipeline.
func (s *scanner) run(ctx context.Context, hosts []target.Host, portList []uint16, pr ports.Protocol, probe prober, out chan<- Result) error {
	if len(hosts) == 0 || len(portList) == 0 {
		return nil
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := s.cfg.MaxConcurrency
	if s.cfg.Concurrency > 0 {
		workers = s.cfg.Concurrency
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 8192 {
		workers = 8192
	}

	jobs := make(chan probeJob, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(scanCtx, jobs, pr, probe, out)
		}()
	}

	// The adaptive controller runs alongside the workers and resizes the
	// concurrency gate as the scan observes the target's behaviour.
	adjustDone := make(chan struct{})
	go func() {
		defer close(adjustDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-scanCtx.Done():
				return
			case <-ticker.C:
				if s.cfg.Concurrency == 0 {
					s.gate.setLimit(s.ctrl.currentLimit())
				}
			}
		}
	}()

	go func() {
		defer close(jobs)
		s.produce(scanCtx, hosts, portList, jobs)
	}()

	wg.Wait()
	cancel()
	<-adjustDone
	return nil
}

// produce emits the probe jobs in the configured order.
func (s *scanner) produce(ctx context.Context, hosts []target.Host, portList []uint16, jobs chan<- probeJob) {
	emit := func(job probeJob) bool {
		select {
		case jobs <- job:
			return true
		case <-ctx.Done():
			return false
		}
	}

	order := s.cfg.Order
	if order == OrderAuto {
		// Scanning a single host port by port keeps the service detection
		// traffic contiguous, while scanning many hosts benefits from
		// spreading the load across addresses.
		if len(hosts) > 8 {
			order = OrderPort
		} else {
			order = OrderHost
		}
	}

	if order == OrderPort {
		for _, p := range portList {
			for _, h := range hosts {
				if !emit(probeJob{host: h, port: p}) {
					return
				}
			}
		}
		return
	}

	for _, h := range hosts {
		for _, p := range portList {
			if !emit(probeJob{host: h, port: p}) {
				return
			}
		}
	}
}

// worker consumes probe jobs until the channel is closed.
func (s *scanner) worker(ctx context.Context, jobs <-chan probeJob, pr ports.Protocol, probe prober, out chan<- Result) {
	for job := range jobs {
		if ctx.Err() != nil {
			return
		}
		if err := s.gate.acquire(ctx); err != nil {
			return
		}
		res := probe(ctx, s, job)
		s.gate.release()

		res.Proto = pr
		select {
		case out <- res:
		case <-ctx.Done():
			return
		}
	}
}

// stats exposes the controller state for reporting.
func (s *scanner) stats() (limit int, ewma time.Duration) {
	limit, ewma, _ = s.ctrl.stats()
	return
}
