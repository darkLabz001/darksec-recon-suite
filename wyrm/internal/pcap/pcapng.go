package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// pcapng block types.
const (
	ngSHB uint32 = 0x0A0D0D0A
	ngIDB uint32 = 0x00000001
	ngPB  uint32 = 0x00000002 // obsolete packet block
	ngSPB uint32 = 0x00000003
	ngEPB uint32 = 0x00000006
)

// ngOption is one option of an interface description block.
type ngOption struct {
	Code uint16
	Data []byte
}

// ngReader decodes a pcapng stream.
type ngReader struct {
	br     *bufio.Reader
	order  binary.ByteOrder
	ifaces []*ngInterface
	link   uint32
	index  int

	// pending holds a block that has been read but not processed yet.
	pendingType uint32
	pendingBody []byte
	hasPending  bool
}

type ngInterface struct {
	linkType uint32
	tsResol  uint8
	tsDiv    uint64
}

// newNGReader reads the section header block and prepares the reader.
func newNGReader(br *bufio.Reader) (*ngReader, error) {
	r := &ngReader{br: br, order: binary.LittleEndian}
	if err := r.readSectionHeader(); err != nil {
		return nil, err
	}
	// The interface description blocks follow the section header, and the
	// link layer type of the capture is not known before they are read.
	// They are consumed eagerly so that the caller can ask for the link
	// type before the first packet.
	for {
		btype, body, err := r.readBlock()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// A section without an interface carries no packet.
				return r, nil
			}
			return nil, err
		}
		if btype == ngIDB {
			if err := r.parseIDB(body); err != nil {
				return nil, err
			}
			continue
		}
		r.pendingType, r.pendingBody, r.hasPending = btype, body, true
		return r, nil
	}
}

// readSectionHeader consumes a section header block and works out the byte
// order of the section.
func (r *ngReader) readSectionHeader() error {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r.br, hdr); err != nil {
		return fmt.Errorf("pcap: pcapng section header: %w", err)
	}
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r.br, magic); err != nil {
		return fmt.Errorf("pcap: pcapng byte order magic: %w", err)
	}
	switch {
	case binary.BigEndian.Uint32(magic) == 0x1A2B3C4D:
		r.order = binary.BigEndian
	case binary.LittleEndian.Uint32(magic) == 0x1A2B3C4D:
		r.order = binary.LittleEndian
	default:
		return fmt.Errorf("pcap: pcapng byte order magic %x is not recognised", magic)
	}
	length := r.order.Uint32(hdr[4:8])
	if length < 16 || length > 1<<24 {
		return fmt.Errorf("pcap: pcapng section header length %d out of range", length)
	}
	body := make([]byte, length-12)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return fmt.Errorf("pcap: pcapng section header: %w", err)
	}
	if trailing := r.order.Uint32(body[len(body)-4:]); trailing != length {
		return fmt.Errorf("pcap: pcapng section header length mismatch")
	}
	return nil
}

// linkType returns the link layer type of the first interface.
func (r *ngReader) linkType() uint32 {
	if len(r.ifaces) > 0 {
		return r.ifaces[0].linkType
	}
	return r.link
}

// next returns the next packet of the stream.
func (r *ngReader) next() (*Packet, error) {
	for {
		var btype uint32
		var body []byte
		if r.hasPending {
			btype, body, r.hasPending = r.pendingType, r.pendingBody, false
		} else {
			var err error
			btype, body, err = r.readBlock()
			if err != nil {
				return nil, err
			}
		}
		switch btype {
		case ngIDB:
			if err := r.parseIDB(body); err != nil {
				return nil, err
			}
		case ngEPB:
			return r.parseEPB(body)
		case ngSPB:
			return r.parseSPB(body)
		case ngPB:
			return r.parsePB(body)
		}
	}
}

// readBlock reads one block and returns its type and body.
func (r *ngReader) readBlock() (uint32, []byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r.br, hdr); err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, nil, io.EOF
		}
		return 0, nil, err
	}
	btype := r.order.Uint32(hdr[0:4])
	length := r.order.Uint32(hdr[4:8])
	if length < 12 || length > 1<<26 {
		return 0, nil, fmt.Errorf("pcap: pcapng block length %d out of range", length)
	}
	// The block is laid out as
	//
	//	block type          4
	//	block total length  4
	//	body                length - 12
	//	block total length  4
	//
	// so eight octets have been read already and length-8 octets are
	// left, the last four of which repeat the total length.
	rest := make([]byte, length-8)
	if _, err := io.ReadFull(r.br, rest); err != nil {
		return 0, nil, fmt.Errorf("pcap: pcapng block body: %w", err)
	}
	if trailing := r.order.Uint32(rest[len(rest)-4:]); trailing != length {
		return 0, nil, fmt.Errorf("pcap: pcapng block length mismatch")
	}
	return btype, rest[:len(rest)-4], nil
}

// parseIDB records an interface description block.
func (r *ngReader) parseIDB(body []byte) error {
	if len(body) < 8 {
		return fmt.Errorf("pcap: pcapng interface description block is too short")
	}
	iface := &ngInterface{
		linkType: uint32(r.order.Uint16(body[0:2])),
		tsResol:  6, // default: microseconds
	}
	opts := body[8:]
	for len(opts) >= 4 {
		code := r.order.Uint16(opts[0:2])
		ln := int(r.order.Uint16(opts[2:4]))
		if code == 0 { // opt_endofopt
			break
		}
		if len(opts) < 4+ln {
			break
		}
		data := opts[4 : 4+ln]
		switch code {
		case 9: // if_tsresol
			if len(data) >= 1 {
				iface.tsResol = data[0]
			}
		case 14: // if_tsoffset
			// ignored, the offset is rarely used
		}
		opts = opts[4+ln+(4-ln%4)%4:]
	}
	iface.tsDiv = 1
	if iface.tsResol&0x80 != 0 {
		// negative exponent, a power of two
		iface.tsDiv = 1 << (iface.tsResol & 0x7f)
	} else {
		iface.tsDiv = uint64(1) << iface.tsResol
	}
	r.ifaces = append(r.ifaces, iface)
	return nil
}

func (r *ngReader) iface(index uint32) *ngInterface {
	if int(index) < len(r.ifaces) {
		return r.ifaces[index]
	}
	if len(r.ifaces) > 0 {
		return r.ifaces[0]
	}
	return &ngInterface{linkType: LinkTypeEthernet, tsDiv: 1000000}
}

// timestamp converts a pcapng timestamp into a wall clock time.
func (r *ngReader) timestamp(iface *ngInterface, ticks uint64) time.Time {
	// ticks are expressed in units of 1/tsDiv of a second.
	sec := int64(ticks / iface.tsDiv)
	rem := ticks % iface.tsDiv
	nsec := int64(float64(rem) * 1e9 / float64(iface.tsDiv))
	return time.Unix(sec, nsec)
}

// parseEPB decodes an enhanced packet block.
func (r *ngReader) parseEPB(body []byte) (*Packet, error) {
	if len(body) < 20 {
		return nil, fmt.Errorf("pcap: pcapng enhanced packet block is too short")
	}
	ifaceIndex := r.order.Uint32(body[0:4])
	tsHigh := r.order.Uint32(body[4:8])
	tsLow := r.order.Uint32(body[8:12])
	captured := int(r.order.Uint32(body[12:16]))
	if captured < 0 || captured > len(body)-20 {
		return nil, fmt.Errorf("pcap: pcapng captured length %d out of range", captured)
	}
	data := make([]byte, captured)
	copy(data, body[20:20+captured])
	iface := r.iface(ifaceIndex)
	ts := r.timestamp(iface, uint64(tsHigh)<<32|uint64(tsLow))
	return &Packet{
		Timestamp: ts,
		Data:      data,
		LinkType:  iface.linkType,
		Index:     r.nextIndex(),
	}, nil
}

// parseSPB decodes a simple packet block.  Simple packets carry no timestamp.
func (r *ngReader) parseSPB(body []byte) (*Packet, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("pcap: pcapng simple packet block is too short")
	}
	captured := int(r.order.Uint32(body[0:4]))
	if captured < 0 || captured > len(body)-4 {
		return nil, fmt.Errorf("pcap: pcapng captured length %d out of range", captured)
	}
	data := make([]byte, captured)
	copy(data, body[4:4+captured])
	iface := r.iface(0)
	return &Packet{
		Timestamp: time.Time{},
		Data:      data,
		LinkType:  iface.linkType,
		Index:     r.nextIndex(),
	}, nil
}

// parsePB decodes the obsolete packet block.
func (r *ngReader) parsePB(body []byte) (*Packet, error) {
	if len(body) < 20 {
		return nil, fmt.Errorf("pcap: pcapng packet block is too short")
	}
	ifaceIndex := r.order.Uint32(body[0:4])
	tsHigh := r.order.Uint32(body[4:8])
	tsLow := r.order.Uint32(body[8:12])
	captured := int(r.order.Uint32(body[12:16]))
	if captured < 0 || captured > len(body)-20 {
		return nil, fmt.Errorf("pcap: pcapng captured length %d out of range", captured)
	}
	data := make([]byte, captured)
	copy(data, body[20:20+captured])
	iface := r.iface(ifaceIndex)
	ts := r.timestamp(iface, uint64(tsHigh)<<32|uint64(tsLow))
	return &Packet{
		Timestamp: ts,
		Data:      data,
		LinkType:  iface.linkType,
		Index:     r.nextIndex(),
	}, nil
}

// nextIndex hands out the running packet number.
func (r *ngReader) nextIndex() int {
	r.index++
	return r.index
}
