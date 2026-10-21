package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

// ConnectScanner performs TCP connect scans.
//
// A connect scan completes the three way handshake, which means it needs no
// special privileges and produces reliable results in every environment.
// It is the default engine.
type ConnectScanner struct {
	scanner *scanner
}

// NewConnectScanner returns a scanner using the TCP connect engine.
func NewConnectScanner(cfg Config) *ConnectScanner {
	return &ConnectScanner{scanner: newScanner(cfg)}
}

// Scan probes every port of every host and reports the results on out.
func (c *ConnectScanner) Scan(ctx context.Context, hosts []target.Host, portList []uint16, out chan<- Result) error {
	return c.scanner.run(ctx, hosts, portList, "tcp", probeConnect, out)
}

// Stats returns the current concurrency limit and the smoothed round trip
// time observed by the adaptive controller.
func (c *ConnectScanner) Stats() (int, time.Duration) { return c.scanner.stats() }

// probeConnect probes a single host and port.
func probeConnect(ctx context.Context, s *scanner, job probeJob) Result {
	res := Result{
		Host: job.host,
		Port: job.port,
	}

	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return res
		}
	}

	start := time.Now()
	conn, addr, err := s.dialHost(ctx, job.host, job.port)
	rtt := time.Since(start)

	if err != nil {
		res.State = classify(err)
		res.Err = err
		res.RTT = rtt
		res.Addr = addr
		if !res.Addr.IsValid() {
			res.Addr = job.host.Any()
		}
		s.ctrl.observe(rtt, true)
		return res
	}

	res.State = StateOpen
	res.RTT = rtt
	res.Addr = addr
	s.ctrl.observe(rtt, false)

	if s.det != nil {
		res.Service = s.detectService(ctx, job, conn, addr)
	} else {
		conn.Close()
	}
	return res
}

// detectService identifies the service behind an open port.
func (s *scanner) detectService(ctx context.Context, job probeJob, conn net.Conn, addr netip.Addr) *detect.ServiceInfo {
	ap := netip.AddrPortFrom(addr, job.port)
	redial := func(ctx context.Context) (net.Conn, error) {
		return s.dialer.DialContext(ctx, networkFor(addr), ap.String())
	}
	return s.det.Detect(ctx, ap, conn, redial)
}

// dialHost connects to a host, racing the address families when the host
// has both an IPv4 and an IPv6 address.
//
// The implementation follows RFC 8305: the first address is attempted
// immediately, the second after a short delay, and the first attempt to
// succeed wins while the other is cancelled.
func (s *scanner) dialHost(ctx context.Context, h target.Host, port uint16) (net.Conn, netip.Addr, error) {
	addrs := h.Addrs()
	switch len(addrs) {
	case 0:
		return nil, netip.Addr{}, errors.New("host has no addresses")
	case 1:
		conn, err := s.dialOne(ctx, addrs[0], port)
		return conn, addrs[0], err
	}

	type attempt struct {
		conn net.Conn
		addr netip.Addr
		err  error
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan attempt, len(addrs))
	started := 0
	var firstErr error
	var firstAddr netip.Addr

	startNext := func() bool {
		if started >= len(addrs) {
			return false
		}
		addr := addrs[started]
		started++
		go func() {
			conn, err := s.dialOne(attemptCtx, addr, port)
			results <- attempt{conn: conn, addr: addr, err: err}
		}()
		return true
	}

	startNext()
	timer := time.NewTimer(s.cfg.HappyDelay)
	defer timer.Stop()

	pending := 1
	for {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				return r.conn, r.addr, nil
			}
			if firstErr == nil {
				firstErr = r.err
				firstAddr = r.addr
			}
			if pending == 0 && started >= len(addrs) {
				return nil, firstAddr, firstErr
			}
			if pending == 0 && startNext() {
				pending++
			}
		case <-timer.C:
			if startNext() {
				pending++
				timer.Reset(s.cfg.HappyDelay)
			}
		case <-ctx.Done():
			return nil, firstAddr, ctx.Err()
		}
	}
}

// dialOne opens a single connection.
func (s *scanner) dialOne(ctx context.Context, addr netip.Addr, port uint16) (net.Conn, error) {
	ap := netip.AddrPortFrom(addr, port)
	return s.dialer.DialContext(ctx, networkFor(addr), ap.String())
}

// networkFor returns the address family network string.
func networkFor(addr netip.Addr) string {
	if addr.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

// classify turns a dial error into a port state.
func classify(err error) State {
	if err == nil {
		return StateOpen
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return StateClosed
	case errors.Is(err, syscall.ECONNRESET):
		return StateClosed
	case errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ENETDOWN),
		errors.Is(err, syscall.EADDRNOTAVAIL),
		errors.Is(err, syscall.EAFNOSUPPORT),
		errors.Is(err, syscall.EPERM):
		return StateFiltered
	case errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, context.DeadlineExceeded):
		return StateFiltered
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateFiltered
	}
	return StateFiltered
}
