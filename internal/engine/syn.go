package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ratelimit"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

// SYNScanner performs half open TCP scans using raw sockets.
//
// A SYN scan never completes the three way handshake, so it is faster and
// leaves fewer traces on the target than a connect scan. It requires the
// CAP_NET_RAW capability, which normally means running as root.
type SYNScanner struct {
	cfg     Config
	limiter *ratelimit.Limiter
	ctrl    *controller
	det     *detect.Detector
}

// NewSYNScanner returns a scanner using the raw SYN engine.
func NewSYNScanner(cfg Config) (*SYNScanner, error) {
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
	if cfg.DetectTimeout <= 0 {
		cfg.DetectTimeout = DefaultDetectTimeout
	}

	s := &SYNScanner{
		cfg:  cfg,
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
	return s, nil
}

// Scan probes every port of every host with a SYN packet.
func (s *SYNScanner) Scan(ctx context.Context, hosts []target.Host, portList []uint16, out chan<- Result) error {
	tx, err := openRawTCP()
	if err != nil {
		return fmt.Errorf("the syn engine needs raw socket access: %w (run as root or grant CAP_NET_RAW)", err)
	}
	defer syscall.Close(tx)

	rx, err := openPacketSocket(s.cfg.Interface)
	if err != nil {
		syscall.Close(tx)
		return fmt.Errorf("opening the packet socket: %w (run as root or grant CAP_NET_RAW)", err)
	}
	defer syscall.Close(rx)

	state := newSynState()
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		s.receiveLoop(ctx, rx, state, out)
	}()

	// Resolve the source address for every target. The kernel is asked
	// through a connectionless socket, so no traffic is generated.
	sources := make(map[netip.Addr]netip.Addr, len(hosts))
	for _, h := range hosts {
		for _, addr := range h.Addrs() {
			if !addr.Is4() {
				continue
			}
			if _, ok := sources[addr]; ok {
				continue
			}
			local, err := localAddrFor(addr)
			if err != nil {
				continue
			}
			sources[addr] = local
			state.addLocal(local)
		}
	}

	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, h := range hosts {
		for _, port := range portList {
			for _, addr := range h.Addrs() {
				if !addr.Is4() {
					continue
				}
				local, ok := sources[addr]
				if !ok {
					continue
				}
				if s.limiter != nil {
					if err := s.limiter.Wait(sendCtx); err != nil {
						break
					}
				}

				srcPort := state.allocatePort(addr)
				deadline := time.Now().Add(s.cfg.Timeout)
				// The probe is registered before it is sent, so that a
				// reply that races the transmission is not lost.
				state.add(addr, port, srcPort, local, deadline)

				packet := buildSYN(synSpec{
					Src:     local,
					Dst:     addr,
					SrcPort: srcPort,
					DstPort: port,
					Seq:     rand.Uint32(),
					Window:  65535,
					TTL:     64,
					ID:      uint16(srcPort),
					Flags:   tcpFlagSYN,
				})
				if err := sendRaw(tx, packet, addr); err != nil {
					state.remove(addr, srcPort)
					continue
				}
			}
		}
	}

	// Wait until every probe has been answered or has timed out. Probes
	// that receive nothing are reported as filtered.
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		if state.outstanding() == 0 {
			break
		}
		select {
		case <-ctx.Done():
			cancel()
			<-recvDone
			return ctx.Err()
		case <-ticker.C:
			for _, res := range state.expire(time.Now()) {
				select {
				case out <- res:
				case <-ctx.Done():
					cancel()
					<-recvDone
					return ctx.Err()
				}
			}
		}
	}

	cancel()
	<-recvDone
	return nil
}

// receiveLoop reads raw frames and resolves the pending probes.
func (s *SYNScanner) receiveLoop(ctx context.Context, fd int, state *synState, out chan<- Result) {
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
				continue
			}
			return
		}
		if n <= 0 {
			continue
		}
		seg, ok := parseTCPFrame(buf[:n])
		if !ok {
			continue
		}
		// Ignore frames that are not addressed to us, which filters out
		// the copies of our own transmissions.
		if !state.isLocal(seg.dstIP) {
			continue
		}

		switch {
		case seg.flags&tcpFlagRST != 0:
			// A reset means the port is closed.
			if state.resolve(seg.srcIP, seg.dstPort, StateClosed) {
				s.emit(ctx, out, Result{
					Host:  target.Host{V4: seg.srcIP},
					Addr:  seg.srcIP,
					Port:  seg.dstPort,
					Proto: "tcp",
					State: StateClosed,
				})
			}
		case seg.flags&tcpFlagSYN != 0 && seg.flags&tcpFlagACK != 0:
			// A syn-ack means the port is open.
			if state.resolve(seg.srcIP, seg.dstPort, StateOpen) {
				res := Result{
					Host:  target.Host{V4: seg.srcIP},
					Addr:  seg.srcIP,
					Port:  seg.dstPort,
					Proto: "tcp",
					State: StateOpen,
				}
				if s.det != nil {
					res.Service = s.detectOpen(ctx, seg.srcIP, seg.dstPort)
				}
				s.emit(ctx, out, res)
			}
		}
	}
}

// emit publishes a result, honouring cancellation.
func (s *SYNScanner) emit(ctx context.Context, out chan<- Result, res Result) {
	select {
	case out <- res:
	case <-ctx.Done():
	}
}

// detectOpen identifies a service using a separate connection, because the
// SYN scan never completes a handshake.
func (s *SYNScanner) detectOpen(ctx context.Context, addr netip.Addr, port uint16) *detect.ServiceInfo {
	ap := netip.AddrPortFrom(addr, port)
	dialer := net.Dialer{Timeout: s.cfg.Timeout, KeepAlive: -1}
	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	conn, err := dialer.DialContext(ctx, network, ap.String())
	if err != nil {
		return nil
	}
	redial := func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, network, ap.String())
	}
	return s.det.Detect(ctx, ap, conn, redial)
}

// synState tracks the probes that are waiting for a reply.
type synState struct {
	mu      sync.Mutex
	pending map[synKey]*synEntry
	ports   map[netip.Addr]uint16
	locals  map[netip.Addr]struct{}
}

// synKey identifies a probe. The source port is the one the scanner chose,
// which the target echoes back as the destination port of its reply.
type synKey struct {
	dst     netip.Addr
	srcPort uint16
}

type synEntry struct {
	port     uint16
	src      netip.Addr
	deadline time.Time
}

func newSynState() *synState {
	return &synState{
		pending: make(map[synKey]*synEntry),
		ports:   make(map[netip.Addr]uint16),
		locals:  make(map[netip.Addr]struct{}),
	}
}

// addLocal records a local address used to send probes.
func (s *synState) addLocal(addr netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locals[addr] = struct{}{}
}

// isLocal reports whether the address is one of ours.
func (s *synState) isLocal(addr netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.locals[addr]
	return ok
}

// allocatePort returns an unused source port for a destination.
func (s *synState) allocatePort(dst netip.Addr) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	port, ok := s.ports[dst]
	if !ok {
		port = uint16(32768 + rand.Intn(20000))
	}
	port++
	if port > 60999 {
		port = 32768
	}
	s.ports[dst] = port
	return port
}

// add registers a probe that is waiting for a reply.
func (s *synState) add(dst netip.Addr, port, srcPort uint16, src netip.Addr, deadline time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[synKey{dst: dst, srcPort: srcPort}] = &synEntry{port: port, src: src, deadline: deadline}
}

// remove drops a probe that could not be sent.
func (s *synState) remove(dst netip.Addr, srcPort uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, synKey{dst: dst, srcPort: srcPort})
}

// resolve marks a pending probe as finished and reports whether it was
// known. The port argument is the destination port of the reply, which is
// the source port we chose for the probe.
func (s *synState) resolve(dst netip.Addr, srcPort uint16, state State) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := synKey{dst: dst, srcPort: srcPort}
	if _, ok := s.pending[key]; !ok {
		return false
	}
	delete(s.pending, key)
	return true
}

// expire removes probes whose deadline has passed and reports them.
func (s *synState) expire(now time.Time) []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Result
	for key, entry := range s.pending {
		if now.After(entry.deadline) {
			delete(s.pending, key)
			out = append(out, Result{
				Host:  target.Host{V4: key.dst},
				Addr:  key.dst,
				Port:  entry.port,
				Proto: "tcp",
				State: StateFiltered,
			})
		}
	}
	return out
}

// outstanding returns the number of probes waiting for a reply.
func (s *synState) outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// openRawTCP opens a raw TCP socket with header inclusion enabled.
func openRawTCP() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return -1, fmt.Errorf("%w", err)
		}
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// openPacketSocket opens an AF_PACKET socket that receives every frame.
func openPacketSocket(iface string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	// Ignore the packets we send ourselves, which removes the need to
	// filter them out in userspace.
	const packetIgnoreOutgoing = 23
	const solPacket = 263
	_ = syscall.SetsockoptInt(fd, solPacket, packetIgnoreOutgoing, 1)

	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			syscall.Close(fd)
			return -1, err
		}
		sa := &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_ALL),
			Ifindex:  ifi.Index,
		}
		if err := syscall.Bind(fd, sa); err != nil {
			syscall.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// sendRaw writes a crafted packet to the network.
func sendRaw(fd int, packet []byte, dst netip.Addr) error {
	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], dst.AsSlice())
	return syscall.Sendto(fd, packet, 0, sa)
}

// parseTCPFrame extracts the TCP header of an Ethernet frame.
func parseTCPFrame(frame []byte) (tcpSegment, bool) {
	var seg tcpSegment
	if len(frame) < 14 {
		return seg, false
	}
	ethType := uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	if ethType == 0x8100 {
		// 802.1Q VLAN tag.
		if len(frame) < 18 {
			return seg, false
		}
		ethType = uint16(frame[16])<<8 | uint16(frame[17])
		offset = 18
	}
	if ethType != 0x0800 {
		return seg, false
	}
	if len(frame) < offset+20 {
		return seg, false
	}
	ip := frame[offset:]
	if ip[0]>>4 != 4 {
		return seg, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return seg, false
	}
	if ip[9] != 6 { // TCP
		return seg, false
	}
	src, ok := netip.AddrFromSlice(ip[12:16])
	if !ok {
		return seg, false
	}
	dst, ok := netip.AddrFromSlice(ip[16:20])
	if !ok {
		return seg, false
	}
	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return seg, false
	}
	seg.srcIP = src
	seg.dstIP = dst
	seg.srcPort = uint16(tcp[0])<<8 | uint16(tcp[1])
	seg.dstPort = uint16(tcp[2])<<8 | uint16(tcp[3])
	seg.flags = tcp[13]
	return seg, true
}

// tcpSegment holds the parts of a TCP header the scanner needs.
type tcpSegment struct {
	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16
	flags   uint8
}

// localAddrFor determines which local address the kernel would use to reach
// a destination, by asking the routing table through a connectionless UDP
// socket. No packets are sent.
func localAddrFor(dst netip.Addr) (netip.Addr, error) {
	network := "udp4"
	if dst.Is6() {
		network = "udp6"
	}
	conn, err := net.Dial(network, netip.AddrPortFrom(dst, 53).String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address type")
	}
	addr, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address")
	}
	return addr.Unmap(), nil
}

// htons converts a 16 bit value to network byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
