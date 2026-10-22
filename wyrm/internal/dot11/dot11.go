package dot11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// FrameType is the 802.11 frame type (two bits of the frame control field).
type FrameType uint8

const (
	TypeManagement FrameType = 0
	TypeControl    FrameType = 1
	TypeData       FrameType = 2
	TypeExtension  FrameType = 3
)

// String renders the frame type.
func (t FrameType) String() string {
	switch t {
	case TypeManagement:
		return "management"
	case TypeControl:
		return "control"
	case TypeData:
		return "data"
	case TypeExtension:
		return "extension"
	}
	return "unknown"
}

// Management subtypes.
const (
	MgmtAssocReq    uint8 = 0
	MgmtAssocResp   uint8 = 1
	MgmtReassocReq  uint8 = 2
	MgmtProbeReq    uint8 = 4
	MgmtProbeResp   uint8 = 5
	MgmtBeacon      uint8 = 8
	MgmtDisassoc    uint8 = 10
	MgmtAuth        uint8 = 11
	MgmtDeauth      uint8 = 12
	MgmtAction      uint8 = 13
	MgmtActionNoAck uint8 = 14
)

// SubtypeName returns a readable name for a management subtype.
func SubtypeName(sub uint8) string {
	switch sub {
	case MgmtAssocReq:
		return "association request"
	case MgmtAssocResp:
		return "association response"
	case MgmtReassocReq:
		return "reassociation request"
	case MgmtProbeReq:
		return "probe request"
	case MgmtProbeResp:
		return "probe response"
	case MgmtBeacon:
		return "beacon"
	case MgmtDisassoc:
		return "disassociation"
	case MgmtAuth:
		return "authentication"
	case MgmtDeauth:
		return "deauthentication"
	case MgmtAction:
		return "action"
	case MgmtActionNoAck:
		return "action (no ack)"
	}
	return fmt.Sprintf("subtype %d", sub)
}

// Radiotap carries the metadata a capture driver attaches to each frame.
type Radiotap struct {
	Version    uint8
	Length     int
	Present    uint32
	HasTSFT    bool
	TSFT       uint64
	HasChannel bool
	Frequency  int
	Channel    int
	HasRSSI    bool
	Signal     int8
	Flags      uint8
}

// Header is the 802.11 MAC header.
type Header struct {
	Version   uint8
	Type      FrameType
	Subtype   uint8
	ToDS      bool
	FromDS    bool
	MoreFrag  bool
	Retry     bool
	PwrMgt    bool
	MoreData  bool
	Protected bool
	Order     bool
	Duration  uint16
	Addr1     net.HardwareAddr
	Addr2     net.HardwareAddr
	Addr3     net.HardwareAddr
	Addr4     net.HardwareAddr
	SeqCtrl   uint16
	SeqNumber uint16
	Fragment  uint16
}

// Frame is a decoded 802.11 frame.
type Frame struct {
	Timestamp time.Time
	Radiotap  Radiotap
	Header    Header
	Body      []byte
	Raw       []byte
}

// BSSID returns the identifier of the basic service set the frame belongs to.
func (f *Frame) BSSID() net.HardwareAddr {
	if f.Header.Type != TypeManagement {
		return nil
	}
	switch f.Header.Subtype {
	case MgmtBeacon, MgmtProbeResp:
		return f.Header.Addr2
	case MgmtAuth, MgmtAssocReq, MgmtReassocReq:
		return f.Header.Addr3
	}
	return nil
}

// Sender returns the transmitting station address.
func (f *Frame) Sender() net.HardwareAddr { return f.Header.Addr2 }

// Receiver returns the receiving station address.
func (f *Frame) Receiver() net.HardwareAddr { return f.Header.Addr1 }

// ErrTruncated is returned when a frame ends before its declared length.
var ErrTruncated = errors.New("dot11: truncated frame")

// Parse decodes a captured 802.11 frame, with or without a radiotap header.
func Parse(data []byte, ts time.Time) (*Frame, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("%w: %d bytes", ErrTruncated, len(data))
	}
	f := &Frame{Timestamp: ts, Raw: data}
	off := 0

	// A radiotap header starts with a version byte of 0 and a length word.
	if data[0] == 0 && len(data) >= 8 {
		rtLen := int(binary.LittleEndian.Uint16(data[2:4]))
		if rtLen >= 8 && rtLen <= len(data) {
			if rt, err := parseRadiotap(data[:rtLen]); err == nil {
				f.Radiotap = rt
				off = rtLen
			}
		}
	}
	if len(data)-off < 24 {
		return nil, fmt.Errorf("%w: mac header needs 24 bytes, have %d", ErrTruncated, len(data)-off)
	}

	h := &f.Header
	b := data[off:]
	h.Version = b[0] & 0x03
	h.Type = FrameType((b[0] >> 2) & 0x03)
	h.Subtype = (b[0] >> 4) & 0x0F
	fl := b[1]
	h.ToDS = fl&0x01 != 0
	h.FromDS = fl&0x02 != 0
	h.MoreFrag = fl&0x04 != 0
	h.Retry = fl&0x08 != 0
	h.PwrMgt = fl&0x10 != 0
	h.MoreData = fl&0x20 != 0
	h.Protected = fl&0x40 != 0
	h.Order = fl&0x80 != 0
	h.Duration = binary.BigEndian.Uint16(b[2:4])
	h.Addr1 = net.HardwareAddr(append([]byte(nil), b[4:10]...))
	h.Addr2 = net.HardwareAddr(append([]byte(nil), b[10:16]...))
	h.Addr3 = net.HardwareAddr(append([]byte(nil), b[16:22]...))
	h.SeqCtrl = binary.BigEndian.Uint16(b[22:24])
	h.SeqNumber = h.SeqCtrl >> 4
	h.Fragment = h.SeqCtrl & 0x0F

	p := off + 24
	if h.ToDS && h.FromDS {
		if len(data)-p < 6 {
			return nil, fmt.Errorf("%w: address 4", ErrTruncated)
		}
		h.Addr4 = net.HardwareAddr(append([]byte(nil), data[p:p+6]...))
		p += 6
	}
	if h.Type == TypeData {
		if h.Subtype&0x08 != 0 { // QoS data
			p += 2
		}
		if h.Order {
			p += 4 // HT control
		}
	}
	if p > len(data) {
		return nil, fmt.Errorf("%w: body", ErrTruncated)
	}
	f.Body = data[p:]
	return f, nil
}

// parseRadiotap decodes the radiotap header, pulling out the timestamp,
// channel and signal strength that matter for a wireless survey.
func parseRadiotap(b []byte) (Radiotap, error) {
	if len(b) < 8 {
		return Radiotap{}, fmt.Errorf("%w: radiotap", ErrTruncated)
	}
	rt := Radiotap{Version: b[0], Length: int(binary.LittleEndian.Uint16(b[2:4]))}
	present := binary.LittleEndian.Uint32(b[4:8])
	rt.Present = present

	// The extended present word, if set, holds another bitmap whose fields
	// follow the ones we already know how to skip.
	ext := present
	off := 8
	if present&0x80000000 != 0 {
		if len(b) < off+4 {
			return rt, nil
		}
		ext = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
	}

	// Walk the standard fields in order. Anything we do not care about still
	// has to be skipped so the ones after it land correctly.
	for bit := 0; bit < 29; bit++ {
		if present&(1<<uint(bit)) == 0 {
			continue
		}
		switch bit {
		case 0: // TSFT
			if off+8 > len(b) {
				return rt, nil
			}
			rt.HasTSFT = true
			rt.TSFT = binary.LittleEndian.Uint64(b[off : off+8])
			off += 8
		case 1: // flags
			if off+1 > len(b) {
				return rt, nil
			}
			rt.Flags = b[off]
			off++
		case 2: // rate
			off++
		case 3: // channel
			if off+2 > len(b) {
				return rt, nil
			}
			rt.HasChannel = true
			rt.Frequency = int(binary.LittleEndian.Uint16(b[off : off+2]))
			chanFlags := binary.LittleEndian.Uint16(b[off+2 : off+4])
			off += 4
			if chanFlags&0x0001 != 0 { // IEEE80211_CHAN_FREQ
				rt.Channel = freqToChannel(rt.Frequency)
			} else {
				rt.Channel = int(chanFlags)
			}
		case 5: // dBm antenna signal
			if off+1 > len(b) {
				return rt, nil
			}
			rt.HasRSSI = true
			rt.Signal = int8(b[off])
			off++
		default:
			n, ok := radiotapFieldSize(bit)
			if !ok {
				return rt, nil // unknown field, stop walking
			}
			off += n
		}
		if off > len(b) {
			return rt, nil
		}
	}
	_ = ext
	return rt, nil
}

// radiotapFieldSize gives the fixed size of the radiotap fields that are not
// handled explicitly above.
var radiotapFieldSizes = map[int]int{
	4: 1, 6: 1, 7: 2, 8: 2, 9: 2, 10: 1, 11: 1, 12: 1, 13: 1,
	14: 2, 15: 2, 16: 1, 17: 1, 18: 8, 19: 3, 20: 4, 21: 12,
	22: 12, 23: 12, 24: 12, 25: 1, 26: 4, 27: 4, 28: 0, 29: 6, 30: 6,
}

func radiotapFieldSize(bit int) (int, bool) {
	n, ok := radiotapFieldSizes[bit]
	return n, ok
}

// freqToChannel maps a centre frequency in MHz to a 2.4/5/6 GHz channel
// number. It returns 0 when the frequency is not a known channel.
func freqToChannel(freq int) int {
	switch {
	case freq == 2484:
		return 14
	case freq >= 2412 && freq <= 2472:
		return (freq - 2407) / 5
	case freq >= 4910 && freq <= 4980:
		return (freq - 4000) / 5
	case freq >= 5000 && freq <= 5900:
		return (freq - 5000) / 5
	case freq >= 5955 && freq <= 7115:
		return (freq - 5950) / 5
	case freq >= 4915 && freq <= 4980:
		return (freq - 4000) / 5
	}
	return 0
}

// ChannelToFreq returns the centre frequency for a channel number in the
// given band.
func ChannelToFreq(channel int, band string) int {
	switch band {
	case "2.4":
		if channel == 14 {
			return 2484
		}
		return 2407 + channel*5
	case "5":
		return 5000 + channel*5
	case "6":
		return 5950 + channel*5
	}
	return 0
}

// BandForFreq classifies a centre frequency into a band name.
func BandForFreq(freq int) string {
	switch {
	case freq >= 2400 && freq <= 2500:
		return "2.4"
	case freq > 5900:
		return "6"
	case freq >= 4900:
		return "5"
	}
	return "unknown"
}
