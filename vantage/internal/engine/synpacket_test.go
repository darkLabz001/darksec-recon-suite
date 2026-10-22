package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestInternetChecksum(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want uint16
	}{
		{"empty", nil, 0xffff},
		{"single zero byte", []byte{0x00}, 0xffff},
		{"two bytes", []byte{0x01, 0x00}, 0xfeff},
		{"known vector", []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}, 0x220d},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := internetChecksum(tt.in); got != tt.want {
				t.Fatalf("internetChecksum(%v) = %#04x, want %#04x", tt.in, got, tt.want)
			}
		})
	}
}

// TestInternetChecksumIsSelfInverse verifies the defining property of the
// one's complement checksum: feeding the result back yields zero.
func TestInternetChecksumIsSelfInverse(t *testing.T) {
	data := []byte{0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00}
	sum := internetChecksum(data)
	combined := append(append([]byte{}, data...), byte(sum>>8), byte(sum))
	if got := internetChecksum(combined); got != 0 {
		t.Fatalf("internet checksum of the checksummed buffer = %#04x, want 0", got)
	}
}

func TestBuildSYNHeader(t *testing.T) {
	spec := synSpec{
		Src:     netip.MustParseAddr("192.168.1.10"),
		Dst:     netip.MustParseAddr("192.168.1.1"),
		SrcPort: 54321,
		DstPort: 443,
		Seq:     0xdeadbeef,
		Window:  65535,
		TTL:     64,
		ID:      0x1234,
		Flags:   tcpFlagSYN,
	}

	packet := buildSYN(spec)
	if len(packet) != ipv4HeaderLen+tcpHeaderLen {
		t.Fatalf("packet length = %d, want %d", len(packet), ipv4HeaderLen+tcpHeaderLen)
	}

	// IPv4 header.
	if packet[0] != 0x45 {
		t.Errorf("version and header length = %#02x, want 0x45", packet[0])
	}
	if got := binary.BigEndian.Uint16(packet[2:4]); got != uint16(len(packet)) {
		t.Errorf("total length = %d, want %d", got, len(packet))
	}
	if got := binary.BigEndian.Uint16(packet[4:6]); got != spec.ID {
		t.Errorf("identification = %#04x, want %#04x", got, spec.ID)
	}
	if got := binary.BigEndian.Uint16(packet[6:8]); got != 0x4000 {
		t.Errorf("fragment offset = %#04x, want 0x4000", got)
	}
	if packet[8] != spec.TTL {
		t.Errorf("ttl = %d, want %d", packet[8], spec.TTL)
	}
	if packet[9] != 6 {
		t.Errorf("protocol = %d, want 6", packet[9])
	}
	if got := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}); got != spec.Src {
		t.Errorf("source address = %s, want %s", got, spec.Src)
	}
	if got := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}); got != spec.Dst {
		t.Errorf("destination address = %s, want %s", got, spec.Dst)
	}

	// TCP header.
	tcp := packet[ipv4HeaderLen:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != spec.SrcPort {
		t.Errorf("source port = %d, want %d", got, spec.SrcPort)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != spec.DstPort {
		t.Errorf("destination port = %d, want %d", got, spec.DstPort)
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != spec.Seq {
		t.Errorf("sequence number = %#08x, want %#08x", got, spec.Seq)
	}
	if tcp[12]>>4 != 5 {
		t.Errorf("data offset = %d, want 5", tcp[12]>>4)
	}
	if tcp[13] != tcpFlagSYN {
		t.Errorf("flags = %#02x, want %#02x", tcp[13], tcpFlagSYN)
	}
	if got := binary.BigEndian.Uint16(tcp[14:16]); got != spec.Window {
		t.Errorf("window = %d, want %d", got, spec.Window)
	}
}

// TestBuildSYNChecksum verifies that the TCP checksum covers the pseudo
// header and the segment, and that it validates once recomputed.
func TestBuildSYNChecksum(t *testing.T) {
	spec := synSpec{
		Src:     netip.MustParseAddr("10.0.0.5"),
		Dst:     netip.MustParseAddr("10.0.0.9"),
		SrcPort: 40000,
		DstPort: 22,
		Seq:     1,
		Window:  1024,
		TTL:     32,
		ID:      7,
		Flags:   tcpFlagSYN,
	}

	packet := buildSYN(spec)
	tcp := packet[ipv4HeaderLen:]
	got := binary.BigEndian.Uint16(tcp[16:18])
	if got == 0 {
		t.Fatal("tcp checksum is zero")
	}

	// Recompute the checksum over a segment whose checksum field is zero.
	clean := append([]byte{}, tcp...)
	binary.BigEndian.PutUint16(clean[16:18], 0)
	want := tcpChecksum(spec.Src, spec.Dst, clean)
	if got != want {
		t.Fatalf("tcp checksum = %#04x, want %#04x", got, want)
	}

	// Validating the complete segment must yield zero.
	full := append([]byte{}, tcp...)
	if c := internetChecksum(pseudoHeader(spec.Src, spec.Dst, full)); c != 0 {
		t.Fatalf("checksum validation = %#04x, want 0", c)
	}
}

// pseudoHeader builds the TCP pseudo header for the tests.
func pseudoHeader(src, dst netip.Addr, segment []byte) []byte {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src.AsSlice())
	copy(pseudo[4:8], dst.AsSlice())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return pseudo
}

func TestBuildSYNDefaults(t *testing.T) {
	packet := buildSYN(synSpec{
		Src: netip.MustParseAddr("10.0.0.1"),
		Dst: netip.MustParseAddr("10.0.0.2"),
	})
	if packet[8] != 64 {
		t.Errorf("default ttl = %d, want 64", packet[8])
	}
	if got := binary.BigEndian.Uint16(packet[ipv4HeaderLen+14 : ipv4HeaderLen+16]); got != 65535 {
		t.Errorf("default window = %d, want 65535", got)
	}
}

func TestParseTCPFrame(t *testing.T) {
	frame := buildEthernetFrame(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.10"),
		443, 54321, tcpFlagSYN|tcpFlagACK,
	)

	seg, ok := parseTCPFrame(frame)
	if !ok {
		t.Fatal("parseTCPFrame failed on a valid frame")
	}
	if seg.srcIP.String() != "192.168.1.1" {
		t.Errorf("source address = %s", seg.srcIP)
	}
	if seg.dstIP.String() != "192.168.1.10" {
		t.Errorf("destination address = %s", seg.dstIP)
	}
	if seg.srcPort != 443 {
		t.Errorf("source port = %d, want 443", seg.srcPort)
	}
	if seg.dstPort != 54321 {
		t.Errorf("destination port = %d, want 54321", seg.dstPort)
	}
	if seg.flags != tcpFlagSYN|tcpFlagACK {
		t.Errorf("flags = %#02x", seg.flags)
	}
}

func TestParseTCPFrameRejectsGarbage(t *testing.T) {
	if _, ok := parseTCPFrame(nil); ok {
		t.Error("an empty frame was accepted")
	}
	if _, ok := parseTCPFrame(make([]byte, 64)); ok {
		t.Error("a frame of zeroes was accepted")
	}
}

func TestParseTCPFrameHandlesVLAN(t *testing.T) {
	frame := buildEthernetFrame(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		80, 1234, tcpFlagRST,
	)
	// Insert an 802.1Q tag after the source and destination MAC addresses.
	vlan := make([]byte, 0, len(frame)+4)
	vlan = append(vlan, frame[:12]...)
	vlan = append(vlan, 0x81, 0x00, 0x00, 0x64)
	vlan = append(vlan, frame[12:]...)

	seg, ok := parseTCPFrame(vlan)
	if !ok {
		t.Fatal("parseTCPFrame failed on a VLAN tagged frame")
	}
	if seg.srcPort != 80 {
		t.Errorf("source port = %d, want 80", seg.srcPort)
	}
}

// buildEthernetFrame assembles a minimal Ethernet frame carrying a TCP
// segment with the given flags.
func buildEthernetFrame(src, dst netip.Addr, srcPort, dstPort uint16, flags uint8) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src.AsSlice())
	copy(ip[16:20], dst.AsSlice())

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	frame := make([]byte, 0, 14+len(ip)+len(tcp))
	frame = append(frame, make([]byte, 12)...) // destination MAC
	frame = append(frame, 0x08, 0x00)          // EtherType: IPv4
	frame = append(frame, ip...)
	frame = append(frame, tcp...)
	return frame
}

func TestHtons(t *testing.T) {
	if got := htons(0x1234); got != 0x3412 {
		t.Errorf("htons(0x1234) = %#04x, want 0x3412", got)
	}
	if got := htons(0x00ff); got != 0xff00 {
		t.Errorf("htons(0x00ff) = %#04x, want 0xff00", got)
	}
}
