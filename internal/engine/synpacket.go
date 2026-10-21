package engine

import (
	"encoding/binary"
	"net/netip"
)

// IPv4 and TCP header constants.
const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20

	// tcpFlagFIN and friends are the TCP control bits.
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagURG = 0x20
)

// synSpec describes a SYN packet to build.
type synSpec struct {
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Window  uint16
	TTL     uint8
	ID      uint16
	// Flags is the TCP control bit set, normally just SYN.
	Flags uint8
}

// buildSYN constructs an IPv4 TCP packet with the SYN flag set.
//
// The IPv4 header is built with a zero checksum because the kernel fills it
// in for sockets opened with IP_HDRINCL. The TCP checksum is computed
// over the pseudo header and is therefore always correct.
func buildSYN(spec synSpec) []byte {
	if spec.TTL == 0 {
		spec.TTL = 64
	}
	if spec.Window == 0 {
		spec.Window = 65535
	}

	packet := make([]byte, ipv4HeaderLen+tcpHeaderLen)

	// IPv4 header.
	packet[0] = 0x45 // version 4, header length 5 words
	packet[1] = 0x00 // type of service
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], spec.ID)
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // don't fragment
	packet[8] = spec.TTL
	packet[9] = 6                                // TCP
	binary.BigEndian.PutUint16(packet[10:12], 0) // checksum, filled by the kernel
	copy(packet[12:16], spec.Src.AsSlice())
	copy(packet[16:20], spec.Dst.AsSlice())

	// TCP header.
	tcp := packet[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], spec.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], spec.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], spec.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], spec.Ack)
	tcp[12] = tcpHeaderLen / 4 << 4 // data offset, no options
	tcp[13] = spec.Flags
	binary.BigEndian.PutUint16(tcp[14:16], spec.Window)
	binary.BigEndian.PutUint16(tcp[16:18], 0) // checksum placeholder
	binary.BigEndian.PutUint16(tcp[18:20], 0) // urgent pointer

	checksum := tcpChecksum(spec.Src, spec.Dst, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], checksum)

	return packet
}

// tcpChecksum computes the TCP checksum over the pseudo header and the
// TCP segment.
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
