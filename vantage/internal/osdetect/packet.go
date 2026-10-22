package osdetect

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// IPv4 and TCP header and option constants.
const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagURG = 0x20

	optEOL    = 0
	optNOP    = 1
	optMSS    = 2
	optWScale = 3
	optSACKOK = 4
	optSACK   = 5
	optTS     = 8
)

// htons converts a 16 bit value to network byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// buildProbeSYN constructs a SYN carrying a realistic option set, so that
// the target answers with its own full option list. The IPv4 checksum is
// left to the kernel (it is filled in for IP_HDRINCL sockets); the TCP
// checksum is computed over the pseudo header.
func buildProbeSYN(src, dst netip.Addr, srcPort, dstPort uint16, seq uint32) []byte {
	// MSS 1460, SACK permitted, timestamp, NOP, window scale 7.
	opts := []byte{
		optMSS, 4, 0x05, 0xb4,
		optSACKOK, 2,
		optTS, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		optNOP,
		optWScale, 3, 7,
	}
	tcpLen := tcpHeaderLen + len(opts)

	packet := make([]byte, ipv4HeaderLen+tcpLen)

	// IPv4 header.
	packet[0] = 0x45 // version 4, header length 5 words
	packet[1] = 0x00 // type of service
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], uint16(srcPort)) // identification
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)          // don't fragment
	packet[8] = 64                                           // TTL
	packet[9] = 6                                            // TCP
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())

	// TCP header.
	tcp := packet[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0) // acknowledgement
	tcp[12] = byte(tcpLen/4) << 4            // data offset, no reserved bits
	tcp[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	copy(tcp[20:], opts)

	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src, dst, tcp))
	return packet
}

// tcpChecksum computes the TCP checksum over the pseudo header and the TCP
// segment.
func tcpChecksum(src, dst netip.Addr, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src.AsSlice())
	copy(pseudo[4:8], dst.AsSlice())
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return internetChecksum(pseudo)
}

// internetChecksum computes the 16 bit one's complement checksum.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// synAck holds the parts of a SYN-ACK the fingerprint needs.
type synAck struct {
	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16
	seq     uint32
	ack     uint32
	flags   uint8
	ttl     uint8
	id      uint16
	window  uint16
	mss     uint16
	wscale  int
	sackOK  bool
	ts      bool
	options string
}

// parseSYNACK extracts the TCP/IP header and options of an Ethernet frame.
func parseSYNACK(frame []byte) (synAck, bool) {
	var s synAck
	if len(frame) < 14 {
		return s, false
	}
	ethType := uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	if ethType == 0x8100 { // 802.1Q VLAN tag
		if len(frame) < 18 {
			return s, false
		}
		ethType = uint16(frame[16])<<8 | uint16(frame[17])
		offset = 18
	}
	if ethType != 0x0800 {
		return s, false
	}
	if len(frame) < offset+ipv4HeaderLen {
		return s, false
	}
	ip := frame[offset:]
	if ip[0]>>4 != 4 {
		return s, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(ip) < ihl {
		return s, false
	}
	if ip[9] != 6 { // TCP
		return s, false
	}
	src, ok := netip.AddrFromSlice(ip[12:16])
	if !ok {
		return s, false
	}
	dst, ok := netip.AddrFromSlice(ip[16:20])
	if !ok {
		return s, false
	}
	s.srcIP = src
	s.dstIP = dst
	s.ttl = ip[8]
	s.id = binary.BigEndian.Uint16(ip[4:6])

	tcp := ip[ihl:]
	if len(tcp) < tcpHeaderLen {
		return s, false
	}
	doff := int(tcp[12]>>4) * 4
	if doff < tcpHeaderLen || len(tcp) < doff {
		return s, false
	}
	s.srcPort = binary.BigEndian.Uint16(tcp[0:2])
	s.dstPort = binary.BigEndian.Uint16(tcp[2:4])
	s.seq = binary.BigEndian.Uint32(tcp[4:8])
	s.ack = binary.BigEndian.Uint32(tcp[8:12])
	s.flags = tcp[13]
	s.window = binary.BigEndian.Uint16(tcp[14:16])

	s.wscale = -1
	parseOptions(tcp[tcpHeaderLen:doff], &s)
	return s, true
}

// parseOptions decodes the TCP options of a segment.
func parseOptions(opts []byte, s *synAck) {
	var names []string
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case optEOL:
			names = append(names, "EOL")
			i = len(opts) // end of the option list
		case optNOP:
			names = append(names, "NOP")
			i++
		default:
			if i+1 >= len(opts) {
				i = len(opts)
				continue
			}
			l := int(opts[i+1])
			if l < 2 || i+l > len(opts) {
				i = len(opts)
				continue
			}
			switch kind {
			case optMSS:
				if l == 4 {
					s.mss = binary.BigEndian.Uint16(opts[i+2 : i+4])
					names = append(names, "MSS")
				}
			case optWScale:
				if l == 3 {
					s.wscale = int(opts[i+2])
					names = append(names, "WScale")
				}
			case optSACKOK:
				s.sackOK = true
				names = append(names, "SACKOK")
			case optSACK:
				names = append(names, "SACK")
			case optTS:
				s.ts = true
				names = append(names, "TS")
			default:
				names = append(names, "?")
			}
			i += l
		}
	}
	s.options = strings.Join(names, ",")
}
