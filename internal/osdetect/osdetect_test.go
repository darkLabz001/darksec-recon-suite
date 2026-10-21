package osdetect

import (
	"net/netip"
	"strings"
	"testing"
)

// buildFrame constructs a SYN-ACK Ethernet frame with the given header
// values and a raw TCP option list.
func buildFrame(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, ttl, id uint8, opts []byte) []byte {
	t.Helper()
	ihl := 20
	tcpLen := 20 + len(opts)
	frame := make([]byte, 14+ihl+tcpLen)

	// Ethernet header: 12 bytes of addresses, then ethertype IPv4.
	frame[12] = 0x08
	frame[13] = 0x00

	ip := frame[14:]
	ip[0] = 0x45
	ip[8] = ttl
	ip[9] = 6 // TCP
	ip[4] = id
	copy(ip[12:16], src.AsSlice())
	copy(ip[16:20], dst.AsSlice())

	tcp := ip[ihl:]
	tcp[0] = byte(srcPort >> 8)
	tcp[1] = byte(srcPort)
	tcp[2] = byte(dstPort >> 8)
	tcp[3] = byte(dstPort)
	tcp[4] = byte(seq >> 24)
	tcp[5] = byte(seq >> 16)
	tcp[6] = byte(seq >> 8)
	tcp[7] = byte(seq)
	tcp[8] = byte(ack >> 24)
	tcp[9] = byte(ack >> 16)
	tcp[10] = byte(ack >> 8)
	tcp[11] = byte(ack)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = flags
	tcp[14] = byte(window >> 8)
	tcp[15] = byte(window)
	copy(tcp[20:], opts)
	return frame
}

func TestParseSYNACK(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("192.0.2.1")

	// MSS 1460, SACK permitted, timestamp, NOP, window scale 7.
	opts := []byte{
		2, 4, 0x05, 0xb4,
		4, 2,
		8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
		1,
		3, 3, 7,
	}

	frame := buildFrame(t, src, dst, 443, 45678, 0x11223344, 0x01020305, tcpFlagSYN|tcpFlagACK, 64240, 64, 0x42, opts)

	s, ok := parseSYNACK(frame)
	if !ok {
		t.Fatal("the frame was not parsed")
	}
	if s.srcIP != src || s.dstIP != dst {
		t.Errorf("addresses = %s -> %s, want %s -> %s", s.srcIP, s.dstIP, src, dst)
	}
	if s.ttl != 64 {
		t.Errorf("ttl = %d, want 64", s.ttl)
	}
	if s.window != 64240 {
		t.Errorf("window = %d, want 64240", s.window)
	}
	if s.mss != 1460 {
		t.Errorf("mss = %d, want 1460", s.mss)
	}
	if s.wscale != 7 {
		t.Errorf("window scale = %d, want 7", s.wscale)
	}
	if !s.sackOK {
		t.Error("SACK permitted was not detected")
	}
	if !s.ts {
		t.Error("timestamp was not detected")
	}
	if s.options != "MSS,SACKOK,TS,NOP,WScale" {
		t.Errorf("options = %q, want %q", s.options, "MSS,SACKOK,TS,NOP,WScale")
	}
}

func TestParseSYNACKRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00, 0x01, 0x02},
		make([]byte, 40),
	}
	for i, b := range cases {
		if _, ok := parseSYNACK(b); ok {
			t.Errorf("case %d: a garbage frame was accepted", i)
		}
	}
}

func TestInitialTTL(t *testing.T) {
	cases := map[uint8]uint8{
		0:   64,
		52:  64,
		64:  64,
		65:  128,
		120: 128,
		128: 128,
		129: 255,
		250: 255,
		255: 255,
	}
	for in, want := range cases {
		if got := initialTTL(in); got != want {
			t.Errorf("initialTTL(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestMatchLinux(t *testing.T) {
	fp := Fingerprint{
		TTL: 64, Window: 64240, MSS: 1460, WindowScale: 7,
		SACKOK: true, Timestamp: true, Options: "MSS,SACKOK,TS,NOP,WScale",
	}
	matches := classify(fp)
	if len(matches) == 0 {
		t.Fatal("no matches returned")
	}
	if matches[0].Name != "Linux" {
		t.Errorf("top match = %q, want Linux", matches[0].Name)
	}
	if matches[0].Accuracy != 100 {
		t.Errorf("accuracy = %d, want 100", matches[0].Accuracy)
	}
}

func TestMatchWindows(t *testing.T) {
	fp := Fingerprint{
		TTL: 128, Window: 8192, MSS: 1460, WindowScale: 8,
		SACKOK: true, Timestamp: true, Options: "MSS,NOP,WScale,NOP,NOP,SACKOK,NOP,TS",
	}
	matches := classify(fp)
	if matches[0].Name != "Windows" {
		t.Errorf("top match = %q, want Windows", matches[0].Name)
	}
}

func TestMatchHandlesHopReduction(t *testing.T) {
	// A Linux host behind a router appears with a reduced TTL.
	fp := Fingerprint{
		TTL: 52, Window: 64240, MSS: 1460, WindowScale: 7,
		SACKOK: true, Timestamp: true, Options: "MSS,SACKOK,TS,NOP,WScale",
	}
	matches := classify(fp)
	if matches[0].Name != "Linux" {
		t.Errorf("top match = %q, want Linux (TTL should be rounded up)", matches[0].Name)
	}
}

func TestMatchSortedByAccuracy(t *testing.T) {
	fp := Fingerprint{TTL: 64, Window: 1, MSS: 1, WindowScale: -1}
	matches := classify(fp)
	for i := 1; i < len(matches); i++ {
		if matches[i].Accuracy > matches[i-1].Accuracy {
			t.Fatalf("matches are not sorted: %d then %d", matches[i-1].Accuracy, matches[i].Accuracy)
		}
	}
	if strings.TrimSpace(matches[0].Name) == "" {
		t.Error("the best match has no name")
	}
}

func TestBuildProbeSYN(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("192.0.2.10")

	pkt := buildProbeSYN(src, dst, 45678, 443, 0x01020304)

	// IP header: 20 bytes + TCP header: 40 bytes (20 + 20 of options).
	if len(pkt) != 20+40 {
		t.Fatalf("packet length = %d, want %d", len(pkt), 60)
	}
	ip := pkt[:20]
	if ip[0] != 0x45 {
		t.Errorf("ip version/ihl = 0x%02x, want 0x45", ip[0])
	}
	if ip[9] != 6 {
		t.Errorf("ip protocol = %d, want 6", ip[9])
	}
	if string(ip[12:16]) != string(src.AsSlice()) {
		t.Errorf("ip source = %v, want %v", ip[12:16], src.AsSlice())
	}
	if string(ip[16:20]) != string(dst.AsSlice()) {
		t.Errorf("ip destination = %v, want %v", ip[16:20], dst.AsSlice())
	}

	tcp := pkt[20:]
	if uint16(tcp[0])<<8|uint16(tcp[1]) != 45678 {
		t.Errorf("source port wrong")
	}
	if uint16(tcp[2])<<8|uint16(tcp[3]) != 443 {
		t.Errorf("destination port wrong")
	}
	if tcp[13] != tcpFlagSYN {
		t.Errorf("flags = 0x%02x, want SYN", tcp[13])
	}
	if tcp[12]>>4 != 10 {
		t.Errorf("data offset = %d words, want 10", tcp[12]>>4)
	}
	// The options must be MSS, SACKOK, TS, NOP, WScale.
	if tcp[20] != 2 || tcp[22] != 0x05 || tcp[23] != 0xb4 {
		t.Errorf("MSS option wrong: %v", tcp[20:24])
	}
}

func TestInternetChecksum(t *testing.T) {
	if got := internetChecksum([]byte{0x00, 0x01}); got != 0xfffe {
		t.Errorf("checksum of 0x0001 = 0x%04x, want 0xfffe", got)
	}
	// The checksum of a message and its checksum is zero, because the sum
	// of a value and its one's complement is all ones.
	msg := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00}
	cs := internetChecksum(msg)
	buf := append(append([]byte{}, msg...), byte(cs>>8), byte(cs))
	if got := internetChecksum(buf); got != 0x0000 {
		t.Errorf("checksum self-check = 0x%04x, want 0x0000", got)
	}
}

func TestLocalAddrForLoopback(t *testing.T) {
	addr, err := localAddrFor(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("localAddrFor: %v", err)
	}
	if !addr.Is4() || addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("local address = %s, want 127.0.0.1", addr)
	}
}
