package osdetect

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Detector fingerpints the TCP/IP stack of a remote host.
type Detector struct {
	// Timeout bounds the wait for the SYN-ACK.
	Timeout time.Duration
}

// New returns a detector with the given reply timeout.
func New(timeout time.Duration) *Detector {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Detector{Timeout: timeout}
}

// Probe sends a SYN to addr:port and matches the SYN-ACK against the
// database. It requires the CAP_NET_RAW capability, because it crafts and
// reads raw packets.
func (d *Detector) Probe(ctx context.Context, addr netip.Addr, port uint16) (*Result, error) {
	if !addr.Is4() {
		return nil, errors.New("os detection supports IPv4 targets only")
	}
	local, err := localAddrFor(addr)
	if err != nil {
		return nil, err
	}

	tx, err := openRawTCP()
	if err != nil {
		return nil, fmt.Errorf("os detection needs raw socket access: %w (run as root or grant CAP_NET_RAW)", err)
	}
	defer syscall.Close(tx)

	rx, err := openPacketSocket()
	if err != nil {
		return nil, fmt.Errorf("opening the packet socket: %w", err)
	}
	defer syscall.Close(rx)

	srcPort := uint16(40000 + rand.Intn(20000))
	seq := rand.Uint32()

	packet := buildProbeSYN(local, addr, srcPort, port, seq)
	if err := sendRaw(tx, packet, addr); err != nil {
		return nil, err
	}

	buf := make([]byte, 65536)
	deadline := time.Now().Add(d.Timeout)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, errors.New("no syn-ack received before the timeout")
		}

		n, _, err := syscall.Recvfrom(rx, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return nil, err
		}
		if n <= 0 {
			continue
		}

		s, ok := parseSYNACK(buf[:n])
		if !ok {
			continue
		}
		// The reply carries our chosen source port as its destination port
		// and acknowledges our sequence number, which is what tells a
		// genuine answer apart from our own retransmission and unrelated
		// traffic.
		if s.dstPort != srcPort {
			continue
		}
		if s.flags&tcpFlagSYN == 0 || s.flags&tcpFlagACK == 0 || s.ack != seq+1 {
			continue
		}

		fp := Fingerprint{
			TTL:         s.ttl,
			InitialTTL:  initialTTL(s.ttl),
			Window:      s.window,
			MSS:         s.mss,
			WindowScale: s.wscale,
			SACKOK:      s.sackOK,
			Timestamp:   s.ts,
			IPID:        s.id,
			Options:     s.options,
		}
		matches := classify(fp)
		res := &Result{Addr: addr, Fingerprint: fp, Candidates: matches}
		if len(matches) > 0 {
			res.OS = matches[0].Name
			res.Description = matches[0].Description
			res.Accuracy = matches[0].Accuracy
		}
		return res, nil
	}
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
//
// The socket carries a receive timeout so that a cancelled probe is noticed
// promptly. Outgoing packets are not filtered by the kernel because the
// reply to a probe of a local address is generated locally.
func openPacketSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	timeout := syscall.Timeval{Sec: 0, Usec: 200 * 1000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// sendRaw writes a crafted packet to the network.
func sendRaw(fd int, packet []byte, dst netip.Addr) error {
	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], dst.AsSlice())
	return syscall.Sendto(fd, packet, 0, sa)
}

// localAddrFor determines which local address the kernel would use to reach
// a destination, by asking the routing table through a connectionless UDP
// socket. No packets are sent.
func localAddrFor(dst netip.Addr) (netip.Addr, error) {
	conn, err := net.Dial("udp4", netip.AddrPortFrom(dst, 53).String())
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
