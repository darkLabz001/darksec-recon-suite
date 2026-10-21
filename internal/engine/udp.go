package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

// UDPScanner probes UDP ports.
//
// UDP has no handshake, so the state of a port is inferred from the way the
// service reacts to a probe datagram: a reply means the port is open, an
// ICMP port unreachable (which the kernel surfaces as ECONNREFUSED on a
// connected socket) means the port is closed, and silence means the port is
// filtered.
type UDPScanner struct {
	scanner *scanner
}

// NewUDPScanner returns a scanner using the UDP engine.
func NewUDPScanner(cfg Config) (*UDPScanner, error) {
	return &UDPScanner{scanner: newScanner(cfg)}, nil
}

// Scan probes every UDP port of every host and reports the results on out.
func (u *UDPScanner) Scan(ctx context.Context, hosts []target.Host, portList []uint16, out chan<- Result) error {
	return u.scanner.run(ctx, hosts, portList, "udp", probeUDP, out)
}

// Stats returns the current concurrency limit and the smoothed round trip
// time observed by the adaptive controller.
func (u *UDPScanner) Stats() (int, time.Duration) { return u.scanner.stats() }

// probeUDP probes a single host and port.
func probeUDP(ctx context.Context, s *scanner, job probeJob) Result {
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
	addr, data, err := s.udpExchange(ctx, job)
	res.RTT = time.Since(start)

	if err != nil {
		res.State = classifyUDP(err)
		res.Err = err
		res.Addr = addr
		if !res.Addr.IsValid() {
			res.Addr = job.host.Any()
		}
		s.ctrl.observe(res.RTT, true)
		return res
	}

	res.State = StateOpen
	res.Addr = addr
	s.ctrl.observe(res.RTT, false)
	res.Service = s.udpService(job.port, data)
	return res
}

// udpExchange sends the probe datagram to every address of the host and
// waits for the first reply.
//
// The addresses are probed in parallel with a stagger, following the spirit
// of RFC 8305: the first address is tried immediately and the others follow
// after a short delay, so a broken address family does not delay the whole
// probe.
func (s *scanner) udpExchange(ctx context.Context, job probeJob) (netip.Addr, []byte, error) {
	addrs := job.host.Addrs()
	if len(addrs) == 0 {
		return netip.Addr{}, nil, errors.New("host has no addresses")
	}

	type exchange struct {
		addr netip.Addr
		data []byte
		err  error
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan exchange, len(addrs))
	payload := udpPayload(job.port)

	var wg sync.WaitGroup
	for i, addr := range addrs {
		if i > 0 {
			// Stagger the remaining address families so that a black
			// holed family does not hold up the probe.
			select {
			case <-probeCtx.Done():
				return netip.Addr{}, nil, probeCtx.Err()
			case <-time.After(time.Duration(i) * s.cfg.HappyDelay):
			}
		}
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			data, err := s.udpProbeOne(probeCtx, a, job.port, payload)
			results <- exchange{addr: a, data: data, err: err}
		}(addr)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var firstErr error
	var firstAddr netip.Addr
	refused := false
	var refusedAddr netip.Addr
	for r := range results {
		if r.err == nil {
			return r.addr, r.data, nil
		}
		if errors.Is(r.err, syscall.ECONNREFUSED) {
			refused = true
			refusedAddr = r.addr
		}
		if firstErr == nil {
			firstErr = r.err
			firstAddr = r.addr
		}
	}

	if refused {
		return refusedAddr, nil, syscall.ECONNREFUSED
	}
	if firstErr == nil {
		firstErr = context.DeadlineExceeded
	}
	return firstAddr, nil, firstErr
}

// udpProbeOne talks to a single address.
func (s *scanner) udpProbeOne(ctx context.Context, addr netip.Addr, port uint16, payload []byte) ([]byte, error) {
	conn, err := s.dialUDP(ctx, addr, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(s.cfg.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// An empty datagram is still sent: it makes a closed port answer with
	// an ICMP port unreachable, which is the primary signal of the scan.
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// dialUDP opens a connected UDP socket to the destination.
func (s *scanner) dialUDP(ctx context.Context, addr netip.Addr, port uint16) (net.Conn, error) {
	network := "udp4"
	if addr.Is6() {
		network = "udp6"
	}

	dialer := net.Dialer{Timeout: s.cfg.Timeout, KeepAlive: -1}
	if s.cfg.SourceAddr.IsValid() && s.cfg.SourceAddr.Is4() == addr.Is4() {
		dialer.LocalAddr = &net.UDPAddr{IP: s.cfg.SourceAddr.AsSlice()}
	}
	return dialer.DialContext(ctx, network, netip.AddrPortFrom(addr, port).String())
}

// udpService identifies the service behind a UDP port from the reply it
// sent, combining the port number with the shape of the response.
func (s *scanner) udpService(port uint16, data []byte) *detect.ServiceInfo {
	if len(data) == 0 {
		return nil
	}

	info := &detect.ServiceInfo{
		Method:     "udp",
		Confidence: 0.8,
	}

	switch {
	case port == 53 || looksLikeDNS(data):
		info.Service = "dns"
		info.Product, info.Version = dnsVersion(data)
	case port == 123 || looksLikeNTP(data):
		info.Service = "ntp"
	case port == 161 || port == 162 || looksLikeSNMP(data):
		info.Service = "snmp"
	case port == 137 || port == 138 || looksLikeNetBIOS(data):
		info.Service = "netbios"
	case port == 1900:
		info.Service = "ssdp"
	case port == 623:
		info.Service = "ipmi"
	case port == 69:
		info.Service = "tftp"
	case port == 7:
		info.Service = "echo"
	case port == 9:
		info.Service = "discard"
	case port == 19:
		info.Service = "chargen"
	case port == 514:
		info.Service = "syslog"
	case port == 5353:
		info.Service = "mdns"
	case port == 11211:
		info.Service = "memcached"
	}

	// The reply of many services carries readable text that the
	// fingerprint database understands.
	if s.det != nil {
		if text := printableText(data); text != "" {
			if extra := s.det.Fingerprint(text); extra != nil {
				if extra.Service != "" && extra.Service != "unknown" {
					info.Service = extra.Service
				}
				if extra.Product != "" {
					info.Product = extra.Product
				}
				if extra.Version != "" {
					info.Version = extra.Version
				}
				if extra.CPE != "" {
					info.CPE = extra.CPE
				}
				info.Banner = text
				info.RawText = text
				if extra.Version != "" {
					info.Confidence = 1.0
				}
			}
		}
	}

	if info.Service == "" {
		return nil
	}
	if info.CPE == "" && info.Product != "" && info.Version != "" {
		info.CPE = "cpe:2.3:a:" + strings.ToLower(info.Product) + ":" +
			strings.ToLower(info.Product) + ":" + info.Version + ":*:*:*:*:*:*:*"
	}
	return info
}

// looksLikeDNS reports whether the data looks like a DNS response.
func looksLikeDNS(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	// The response bit must be set and the question count must be sane.
	if data[2]&0x80 == 0 {
		return false
	}
	qd := int(data[4])<<8 | int(data[5])
	an := int(data[6])<<8 | int(data[7])
	return qd <= 16 && an <= 64
}

// looksLikeNTP reports whether the data looks like an NTP response.
func looksLikeNTP(data []byte) bool {
	if len(data) < 48 {
		return false
	}
	version := (data[0] >> 3) & 0x07
	mode := data[0] & 0x07
	return version >= 2 && version <= 4 && mode <= 7
}

// looksLikeSNMP reports whether the data looks like an SNMP message.
func looksLikeSNMP(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	if data[0] != 0x30 {
		return false
	}
	length := int(data[1])
	return length == len(data)-2 || length+2 <= len(data)
}

// looksLikeNetBIOS reports whether the data looks like a NetBIOS datagram.
func looksLikeNetBIOS(data []byte) bool {
	if len(data) < 50 {
		return false
	}
	// A name service response carries the broadcast flag and at least one
	// answer record.
	return int(data[2])<<8|int(data[3])&0x80 != 0
}

// dnsVersion extracts the TXT answer of a CHAOS version.bind response.
func dnsVersion(data []byte) (product, version string) {
	if len(data) < 12 {
		return "", ""
	}
	qd := int(data[4])<<8 | int(data[5])
	an := int(data[6])<<8 | int(data[7])

	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipDNSName(data, off)
		if err != nil {
			return "", ""
		}
		off += 4 // type and class
	}
	for i := 0; i < an; i++ {
		var err error
		off, err = skipDNSName(data, off)
		if err != nil {
			return "", ""
		}
		if off+10 > len(data) {
			return "", ""
		}
		rtype := int(data[off])<<8 | int(data[off+1])
		rdlen := int(data[off+8])<<8 | int(data[off+9])
		off += 10
		if off+rdlen > len(data) {
			return "", ""
		}
		if rtype == 0x0010 { // TXT
			txt := data[off : off+rdlen]
			for p := 0; p < len(txt); {
				l := int(txt[p])
				p++
				if p+l > len(txt) {
					break
				}
				value := strings.TrimSpace(string(txt[p : p+l]))
				p += l
				if value == "" {
					continue
				}
				if version == "" {
					version = value
				}
			}
		}
		off += rdlen
	}
	return "", version
}

// skipDNSName advances past a (possibly compressed) domain name.
func skipDNSName(data []byte, off int) (int, error) {
	for {
		if off >= len(data) {
			return 0, errors.New("dns name out of bounds")
		}
		l := int(data[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			return off + 2, nil
		default:
			off += l + 1
		}
	}
}

// printableText extracts the readable portion of a binary payload.
//
// Binary protocols answer with a mixture of structure and text. Only
// runs of at least minPrintableRun printable bytes are kept, which keeps
// incidental bytes from a structured reply from looking like a banner.
const minPrintableRun = 4

func printableText(data []byte) string {
	var sb strings.Builder
	run := make([]byte, 0, 64)

	flush := func() {
		if len(run) >= minPrintableRun {
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.Write(run)
		}
		run = run[:0]
	}

	for _, b := range data {
		switch {
		case b >= 0x20 && b < 0x7f:
			run = append(run, b)
		case b == '\n' || b == '\r' || b == '\t':
			run = append(run, ' ')
		default:
			flush()
		}
	}
	flush()

	text := strings.TrimSpace(sb.String())
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}

// classifyUDP turns a UDP error into a port state.
func classifyUDP(err error) State {
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
		errors.Is(err, syscall.EACCES),
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
