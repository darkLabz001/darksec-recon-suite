// Package engine implements the scan engines: TCP connect, TCP SYN and UDP.
//
// The engines share a common model: a bounded pipeline of probe jobs is
// consumed by a pool of workers, each probe is paced by an optional rate
// limiter and an adaptive concurrency gate, and every observation is
// reported as a Result.
package engine

import (
	"net/netip"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/osdetect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

// State describes the outcome of a single port probe.
type State string

const (
	// StateOpen means the port accepted a connection.
	StateOpen State = "open"
	// StateClosed means the port actively refused the connection (RST).
	StateClosed State = "closed"
	// StateFiltered means the probe produced no conclusive response.
	StateFiltered State = "filtered"
)

// Result describes the outcome of probing a single port on a single host.
type Result struct {
	// Host is the logical target, which may carry both address families.
	Host target.Host
	// Addr is the address that actually produced the result.
	Addr netip.Addr
	// Port is the probed port.
	Port uint16
	// Proto is the transport protocol.
	Proto ports.Protocol
	// State is the probe outcome.
	State State
	// RTT is the time taken to complete the probe.
	RTT time.Duration
	// Service holds detection results for open ports.
	Service *detect.ServiceInfo
	// OS holds the operating system fingerprint of the host, when OS
	// detection is enabled. It is reported on a dedicated result once per
	// host, with a zero port.
	OS *osdetect.Result
	// Err is the underlying error, if any.
	Err error
}

// Open reports whether the result indicates an open port.
func (r Result) Open() bool { return r.State == StateOpen }

// Endpoint returns the "ip:port" form of the probed endpoint.
func (r Result) Endpoint() string {
	return netip.AddrPortFrom(r.Addr, r.Port).String()
}
