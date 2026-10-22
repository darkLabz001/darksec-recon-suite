// Package pcap reads and writes capture files without linking against
// libpcap. It understands the classic pcap format in both byte orders and
// both timestamp resolutions, and the pcapng format.
//
// The auditor deliberately avoids a cgo dependency: the tool runs on hosts
// where libpcap headers are not installed, and capture itself is delegated
// to tcpdump.
package pcap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Link types the auditor understands.
const (
	LinkTypeEthernet          uint32 = 1
	LinkTypeIEEE80211         uint32 = 105
	LinkTypeIEEE80211Radiotap uint32 = 127
	LinkTypeIEEE80211Radio    uint32 = 163
)

// ErrUnsupported is returned for capture files the reader cannot decode.
var ErrUnsupported = errors.New("pcap: unsupported capture format")

// Packet is one captured frame.
type Packet struct {
	Timestamp time.Time
	Data      []byte
	LinkType  uint32
	Index     int
}

// Reader streams packets out of a capture file.
type Reader struct {
	br       *bufio.Reader
	closer   io.Closer
	order    binary.ByteOrder
	nano     bool
	linkType uint32
	snaplen  uint32
	ng       *ngReader
	index    int
}

// Open opens a capture file for reading. Both pcap and pcapng files are
// accepted; the format is detected from the first four bytes.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	r.closer = f
	return r, nil
}

// NewReader reads a capture stream from r.  Both pcap and pcapng streams are
// accepted; the format is detected from the first four bytes.  The reader does
// not close r.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("pcap: %w", err)
	}
	switch {
	case bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}):
		ng, err := newNGReader(br)
		if err != nil {
			return nil, err
		}
		return &Reader{br: br, ng: ng}, nil
	case bytes.Equal(magic, []byte{0xa1, 0xb2, 0xc3, 0xd4}):
		return newReader(br, nil, binary.BigEndian, false)
	case bytes.Equal(magic, []byte{0xd4, 0xc3, 0xb2, 0xa1}):
		return newReader(br, nil, binary.LittleEndian, false)
	case bytes.Equal(magic, []byte{0xa1, 0xb2, 0x3c, 0x4d}):
		return newReader(br, nil, binary.BigEndian, true)
	case bytes.Equal(magic, []byte{0x4d, 0x3c, 0xb2, 0xa1}):
		return newReader(br, nil, binary.LittleEndian, true)
	}
	return nil, fmt.Errorf("%w: magic %x", ErrUnsupported, magic)
}

func newReader(br *bufio.Reader, c io.Closer, order binary.ByteOrder, nano bool) (*Reader, error) {
	// The global header is twenty four octets:
	//
	//	magic            4
	//	version major    2
	//	version minor    2
	//	this zone        4
	//	sig figures      4
	//	snap length      4
	//	network          4
	//
	// The magic has only been peeked at, so it is still the first four
	// octets of the header.
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(br, hdr); err != nil {
		if c != nil {
			c.Close()
		}
		return nil, fmt.Errorf("pcap: global header: %w", err)
	}
	r := &Reader{br: br, closer: c, order: order, nano: nano}
	r.snaplen = order.Uint32(hdr[16:20])
	r.linkType = order.Uint32(hdr[20:24])
	return r, nil
}

// LinkType returns the link layer type of the capture.
func (r *Reader) LinkType() uint32 {
	if r.ng != nil {
		return r.ng.linkType()
	}
	return r.linkType
}

// Close releases the underlying file.
func (r *Reader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// Next returns the next packet, or io.EOF at the end of the file.
func (r *Reader) Next() (*Packet, error) {
	if r.ng != nil {
		return r.ng.next()
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r.br, hdr); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	sec := int64(r.order.Uint32(hdr[0:4]))
	frac := int64(r.order.Uint32(hdr[4:8]))
	incl := int(r.order.Uint32(hdr[8:12]))
	if incl < 0 || incl > 1<<26 {
		return nil, fmt.Errorf("pcap: implausible packet length %d", incl)
	}
	data := make([]byte, incl)
	if _, err := io.ReadFull(r.br, data); err != nil {
		return nil, fmt.Errorf("pcap: packet body: %w", err)
	}
	ns := frac
	if !r.nano {
		ns = frac * 1000
	}
	r.index++
	return &Packet{
		Timestamp: time.Unix(sec, ns),
		Data:      data,
		LinkType:  r.linkType,
		Index:     r.index,
	}, nil
}

// Writer emits a classic pcap file.
type Writer struct {
	w       *bufio.Writer
	closer  io.Closer
	order   binary.ByteOrder
	nano    bool
	linkTyp uint32
	snaplen uint32
	started bool
}

// Create opens path for writing a classic pcap file.
func Create(path string, linkType uint32, snaplen int) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		w:       bufio.NewWriterSize(f, 1<<16),
		closer:  f,
		order:   binary.LittleEndian,
		linkTyp: linkType,
		snaplen: uint32(snaplen),
	}
	if snaplen == 0 {
		w.snaplen = 65535
	}
	return w, nil
}

// Write appends a packet.
func (w *Writer) Write(p *Packet) error {
	if !w.started {
		if err := w.writeHeader(); err != nil {
			return err
		}
		w.started = true
	}
	ts := p.Timestamp
	sec := uint32(ts.Unix())
	frac := uint32(ts.Nanosecond())
	if !w.nano {
		frac /= 1000
	}
	hdr := make([]byte, 16)
	w.order.PutUint32(hdr[0:4], sec)
	w.order.PutUint32(hdr[4:8], frac)
	w.order.PutUint32(hdr[8:12], uint32(len(p.Data)))
	w.order.PutUint32(hdr[12:16], uint32(len(p.Data)))
	if _, err := w.w.Write(hdr); err != nil {
		return err
	}
	_, err := w.w.Write(p.Data)
	return err
}

func (w *Writer) writeHeader() error {
	hdr := make([]byte, 24)
	w.order.PutUint32(hdr[0:4], 0xa1b2c3d4)
	w.order.PutUint16(hdr[4:6], 2)
	w.order.PutUint16(hdr[6:8], 4)
	w.order.PutUint32(hdr[8:12], 0)
	w.order.PutUint32(hdr[12:16], 0)
	w.order.PutUint32(hdr[16:20], w.snaplen)
	w.order.PutUint32(hdr[20:24], w.linkTyp)
	_, err := w.w.Write(hdr)
	return err
}

// Close flushes and closes the file.
func (w *Writer) Close() error {
	if err := w.w.Flush(); err != nil {
		w.closer.Close()
		return err
	}
	return w.closer.Close()
}
