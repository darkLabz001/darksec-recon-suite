package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ngOption builds a pcapng option.
func buildOption(code uint16, value []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:2], code)
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(value)))
	out = append(out, value...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// ngBlock wraps a body in a pcapng block.
func ngBlock(typ uint32, body []byte) []byte {
	total := uint32(12 + len(body))
	out := make([]byte, 8)
	binary.LittleEndian.PutUint32(out[0:4], typ)
	binary.LittleEndian.PutUint32(out[4:8], total)
	out = append(out, body...)
	tail := make([]byte, 4)
	binary.LittleEndian.PutUint32(tail, total)
	return append(out, tail...)
}

// ngSection builds a pcapng file with one interface and the given packets.
func ngSection(linkType uint16, snaplen uint32, packets [][]byte) []byte {
	shb := ngBlock(0x0A0D0D0A, func() []byte {
		body := make([]byte, 16)
		binary.LittleEndian.PutUint32(body[0:4], 0x1A2B3C4D)
		binary.LittleEndian.PutUint16(body[4:6], 1)
		binary.LittleEndian.PutUint16(body[6:8], 0)
		binary.LittleEndian.PutUint64(body[8:16], 0xFFFFFFFFFFFFFFFF)
		body = append(body, buildOption(0, nil)...)
		return body
	}())

	idb := ngBlock(0x00000001, func() []byte {
		body := make([]byte, 8)
		binary.LittleEndian.PutUint16(body[0:2], linkType)
		binary.LittleEndian.PutUint16(body[2:4], 0)
		binary.LittleEndian.PutUint32(body[4:8], snaplen)
		body = append(body, buildOption(9, []byte{6})...) // microseconds
		body = append(body, buildOption(0, nil)...)
		return body
	}())

	var out []byte
	out = append(out, shb...)
	out = append(out, idb...)

	for i, p := range packets {
		epb := ngBlock(0x00000006, func() []byte {
			body := make([]byte, 20)
			binary.LittleEndian.PutUint32(body[0:4], 0)
			// A timestamp of 1.5 seconds in microseconds.
			micros := uint64(1500000)
			binary.LittleEndian.PutUint32(body[4:8], uint32(micros>>32))
			binary.LittleEndian.PutUint32(body[8:12], uint32(micros))
			binary.LittleEndian.PutUint32(body[12:16], uint32(len(p)))
			binary.LittleEndian.PutUint32(body[16:20], uint32(len(p)))
			body = append(body, p...)
			for len(body)%4 != 0 {
				body = append(body, 0)
			}
			body = append(body, buildOption(0, nil)...)
			return body
		}())
		out = append(out, epb...)
		_ = i
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")

	packets := []*Packet{
		{Timestamp: time.Unix(1700000000, 0), Data: []byte{0x01, 0x02, 0x03}},
		{Timestamp: time.Unix(1700000001, 500000000), Data: []byte{0x04, 0x05}},
		{Timestamp: time.Unix(1700000002, 0), Data: bytes.Repeat([]byte{0xAB}, 200)},
	}

	w, err := Create(path, LinkTypeIEEE80211Radiotap, 65535)
	if err != nil {
		t.Fatalf("the writer must open: %v", err)
	}
	for _, p := range packets {
		if err := w.Write(p); err != nil {
			t.Fatalf("the packet must be written: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("the writer must close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("the file must open: %v", err)
	}
	defer r.Close()

	if r.LinkType() != LinkTypeIEEE80211Radiotap {
		t.Errorf("the link type reads %d, want %d", r.LinkType(), LinkTypeIEEE80211Radiotap)
	}

	var got []*Packet
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		got = append(got, p)
	}
	if len(got) != len(packets) {
		t.Fatalf("the file holds %d packets, want %d", len(got), len(packets))
	}
	for i, p := range got {
		if !bytes.Equal(p.Data, packets[i].Data) {
			t.Errorf("the packet %d carries %x, want %x", i, p.Data, packets[i].Data)
		}
		if !p.Timestamp.Equal(packets[i].Timestamp) {
			t.Errorf("the packet %d is stamped %s, want %s", i, p.Timestamp, packets[i].Timestamp)
		}
		if p.Index != i+1 {
			t.Errorf("the packet %d carries the index %d", i, p.Index)
		}
	}
}

func TestOpenRejectsAnUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonsense.bin")
	if err := os.WriteFile(path, []byte("not a capture file at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("a file that is not a capture must be rejected")
	}
}

func TestNewReaderReadsAStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")

	w, err := Create(path, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("the writer must open: %v", err)
	}
	if err := w.Write(&Packet{Timestamp: time.Unix(1700000000, 0), Data: []byte{0xAA, 0xBB}}); err != nil {
		t.Fatalf("the packet must be written: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("the writer must close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the stream must open: %v", err)
	}
	p, err := r.Next()
	if err != nil {
		t.Fatalf("the packet must be read: %v", err)
	}
	if !bytes.Equal(p.Data, []byte{0xAA, 0xBB}) {
		t.Errorf("the packet carries %x", p.Data)
	}
	if r.LinkType() != LinkTypeEthernet {
		t.Errorf("the link type reads %d, want %d", r.LinkType(), LinkTypeEthernet)
	}
}

func TestReadPcapng(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcapng")

	packets := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		{0x05, 0x06},
	}
	if err := os.WriteFile(path, ngSection(uint16(LinkTypeIEEE80211Radiotap), 65535, packets), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("the file must open: %v", err)
	}
	defer r.Close()

	if r.LinkType() != LinkTypeIEEE80211Radiotap {
		t.Errorf("the link type reads %d, want %d", r.LinkType(), LinkTypeIEEE80211Radiotap)
	}

	var got int
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		if !bytes.Equal(p.Data, packets[got]) {
			t.Errorf("the packet %d carries %x, want %x", got, p.Data, packets[got])
		}
		got++
	}
	if got != len(packets) {
		t.Errorf("the file holds %d packets, want %d", got, len(packets))
	}
}

func TestReadPcapngWithNanosecondResolution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcapng")

	// Build the file by hand with a nanosecond timestamp resolution.
	shb := ngBlock(0x0A0D0D0A, func() []byte {
		body := make([]byte, 16)
		binary.LittleEndian.PutUint32(body[0:4], 0x1A2B3C4D)
		binary.LittleEndian.PutUint16(body[4:6], 1)
		binary.LittleEndian.PutUint16(body[6:8], 0)
		binary.LittleEndian.PutUint64(body[8:16], 0xFFFFFFFFFFFFFFFF)
		return append(body, buildOption(0, nil)...)
	}())
	idb := ngBlock(0x00000001, func() []byte {
		body := make([]byte, 8)
		binary.LittleEndian.PutUint16(body[0:2], uint16(LinkTypeEthernet))
		binary.LittleEndian.PutUint32(body[4:8], 65535)
		body = append(body, buildOption(9, []byte{9})...) // nanoseconds
		return append(body, buildOption(0, nil)...)
	}())
	epb := ngBlock(0x00000006, func() []byte {
		body := make([]byte, 20)
		nanos := uint64(1500000000) // 1.5 seconds in nanoseconds
		binary.LittleEndian.PutUint32(body[4:8], uint32(nanos>>32))
		binary.LittleEndian.PutUint32(body[8:12], uint32(nanos))
		binary.LittleEndian.PutUint32(body[12:16], 2)
		binary.LittleEndian.PutUint32(body[16:20], 2)
		body = append(body, 0x42, 0x43)
		body = append(body, buildOption(0, nil)...)
		return body
	}())

	if err := os.WriteFile(path, append(append(shb, idb...), epb...), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("the file must open: %v", err)
	}
	defer r.Close()

	p, err := r.Next()
	if err != nil {
		t.Fatalf("the packet must be read: %v", err)
	}
	if !bytes.Equal(p.Data, []byte{0x42, 0x43}) {
		t.Errorf("the packet carries %x", p.Data)
	}
	if p.Timestamp.Nanosecond() != 500000000 {
		t.Errorf("the packet is stamped %s", p.Timestamp)
	}
}
