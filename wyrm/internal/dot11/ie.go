package dot11

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Information element identifiers used by the auditor.
const (
	IESSID             uint8 = 0
	IESSupportedRates  uint8 = 1
	IEDSParameterSet   uint8 = 3
	IEHTCapability     uint8 = 61
	IERSN              uint8 = 48
	IEVendorSpecific   uint8 = 221
	IEExtendedCaps     uint8 = 255
	IEChannelSwitchAnn uint8 = 36
	IEQuiet            uint8 = 40
	IEPowerConstraint  uint8 = 32
	IECountryInfo      uint8 = 7
	IERobustBSS        uint8 = 57
	IEBSSLoad          uint8 = 10
	IERSNXE            uint8 = 244
)

// RSN information element capability bits.
const (
	RSNCapMFPR uint16 = 0x0040 // management frame protection required
	RSNCapMFPC uint16 = 0x0080 // management frame protection capable
)

// Extended capabilities bits (bit numbers are counted from the least
// significant bit of the first octet).
const (
	ExtCapSAEIdentifiersInUse  = 81
	ExtCapSAEPasswordsExclusiv = 82
	ExtCapSAEPKExclusively     = 88
)

// WFA vendor specific information element subtypes.
const (
	WFASubtypeOWETransitionMode    uint8 = 28
	WFASubtypeTransitionDisableKDE uint8 = 32
	WFASubtypeWFACapabilities      uint8 = 35
	WFASubtypeRSNXOverride         uint8 = 43
)

// Element is one information element.
type Element struct {
	ID     uint8
	ExtID  uint8
	Data   []byte
	Vendor bool
}

// VendorInfo decodes a vendor specific element into its OUI and subtype.
func (e Element) VendorInfo() (oui [3]byte, subtype uint8, ok bool) {
	if !e.Vendor || len(e.Data) < 4 {
		return
	}
	copy(oui[:], e.Data[:3])
	subtype = e.Data[3]
	return oui, subtype, true
}

// ParseElements splits a tagged parameter blob into information elements.
func ParseElements(b []byte) []Element {
	var out []Element
	for len(b) >= 2 {
		id, ln := b[0], int(b[1])
		if len(b) < 2+ln {
			// Truncated element: keep what we have and stop.
			out = append(out, Element{ID: id, Data: append([]byte(nil), b[2:]...)})
			return out
		}
		e := Element{ID: id, Data: append([]byte(nil), b[2:2+ln]...)}
		if id == IEVendorSpecific {
			e.Vendor = true
		}
		out = append(out, e)
		b = b[2+ln:]
	}
	return out
}

// Find returns the first element with the given id.
func Find(els []Element, id uint8) (Element, bool) {
	for _, e := range els {
		if e.ID == id {
			return e, true
		}
	}
	return Element{}, false
}

// FindAll returns every element with the given id.
func FindAll(els []Element, id uint8) []Element {
	var out []Element
	for _, e := range els {
		if e.ID == id {
			out = append(out, e)
		}
	}
	return out
}

// RSNInfo is a decoded RSN information element.
type RSNInfo struct {
	Version         uint16
	GroupCipher     CipherSuite
	PairwiseCiphers []CipherSuite
	AKMs            []AKMSuite
	Capabilities    uint16
	PMKIDs          [][]byte
	GroupMgmtCipher *CipherSuite
	CapabilitiesExt []byte
	HasCapabilities bool
}

// MFPC reports whether the network is management frame protection capable.
func (r *RSNInfo) MFPC() bool { return r.Capabilities&RSNCapMFPC != 0 }

// MFPR reports whether the network requires management frame protection.
func (r *RSNInfo) MFPR() bool { return r.Capabilities&RSNCapMFPR != 0 }

// HasAKM reports whether the given suite is advertised.
func (r *RSNInfo) HasAKM(a AKMSuite) bool {
	for _, k := range r.AKMs {
		if k == a {
			return true
		}
	}
	return false
}

// HasSAE reports whether SAE (WPA3 personal) is offered.
func (r *RSNInfo) HasSAE() bool {
	for _, k := range r.AKMs {
		if k.IsSAE() {
			return true
		}
	}
	return false
}

// HasPSK reports whether the WPA2 personal (PSK) suite is offered.
func (r *RSNInfo) HasPSK() bool {
	for _, k := range r.AKMs {
		if k.IsPSKFamily() {
			return true
		}
	}
	return false
}

// HasOWE reports whether OWE is offered.
func (r *RSNInfo) HasOWE() bool {
	for _, k := range r.AKMs {
		if k.IsOWE() {
			return true
		}
	}
	return false
}

// HasEnterprise reports whether an 802.1X family suite is offered.
func (r *RSNInfo) HasEnterprise() bool {
	for _, k := range r.AKMs {
		if k.IsEnterprise() {
			return true
		}
	}
	return false
}

// ParseRSN decodes an RSN information element body.
func ParseRSN(data []byte) (*RSNInfo, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("dot11: rsn element too short (%d bytes)", len(data))
	}
	r := &RSNInfo{}
	p := 0
	r.Version = binary.LittleEndian.Uint16(data[p:])
	p += 2
	r.GroupCipher = readCipher(data[p:])
	p += 4

	if p+2 > len(data) {
		return r, nil
	}
	n := int(binary.LittleEndian.Uint16(data[p:]))
	p += 2
	for i := 0; i < n && p+4 <= len(data); i++ {
		r.PairwiseCiphers = append(r.PairwiseCiphers, readCipher(data[p:]))
		p += 4
	}
	if p+2 > len(data) {
		return r, nil
	}
	n = int(binary.LittleEndian.Uint16(data[p:]))
	p += 2
	for i := 0; i < n && p+4 <= len(data); i++ {
		r.AKMs = append(r.AKMs, readAKM(data[p:]))
		p += 4
	}
	if p+2 <= len(data) {
		r.Capabilities = binary.LittleEndian.Uint16(data[p:])
		r.HasCapabilities = true
		p += 2
	}
	if p+2 <= len(data) {
		n = int(binary.LittleEndian.Uint16(data[p:]))
		p += 2
		for i := 0; i < n && p+16 <= len(data); i++ {
			r.PMKIDs = append(r.PMKIDs, append([]byte(nil), data[p:p+16]...))
			p += 16
		}
	}
	if p+4 <= len(data) {
		c := readCipher(data[p:])
		r.GroupMgmtCipher = &c
		p += 4
	}
	if p < len(data) {
		r.CapabilitiesExt = append([]byte(nil), data[p:]...)
	}
	return r, nil
}

func readCipher(b []byte) CipherSuite {
	return CipherSuite{OUI: [3]byte{b[0], b[1], b[2]}, Type: b[3]}
}

func readAKM(b []byte) AKMSuite {
	return AKMSuite{OUI: [3]byte{b[0], b[1], b[2]}, Type: b[3]}
}

// ExtCapBit reports whether the given extended capabilities bit is set.
func ExtCapBit(ext []byte, bit uint8) bool {
	idx := bit / 8
	if int(idx) >= len(ext) {
		return false
	}
	return ext[idx]&(1<<(bit%8)) != 0
}

// RSNXE flags of the first octet of the RSN extension element.
//
// The element carries its own length in the low four bits of the first
// octet and the extension flags in the high four bits.
const (
	RSNXEProtectedTWT  uint8 = 0x10
	RSNXESAEHashToElem uint8 = 0x20
	RSNXEFlagSAEPK     uint8 = 0x40
	RSNXEProtectedWUR  uint8 = 0x80
)

// RSNXESAEPK reports whether the RSN extension element signals SAE-PK.
//
// The SAE-PK method replaces the password with a key, so an access point
// that uses it needs a long key rather than a memorable password.
func RSNXESAEPK(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	return data[0]&RSNXEFlagSAEPK != 0
}

// SSIDOf extracts the SSID from a set of elements. A missing or hidden SSID
// is reported as the empty string.
func SSIDOf(els []Element) string {
	e, ok := Find(els, IESSID)
	if !ok {
		return ""
	}
	return strings.TrimRight(string(e.Data), "\x00")
}

// HiddenSSID reports whether the SSID element is present but empty.
func HiddenSSID(els []Element) bool {
	e, ok := Find(els, IESSID)
	return ok && len(e.Data) == 0
}

// Management holds the decoded parts of a management frame.
type Management struct {
	Kind           string
	Timestamp      uint64
	BeaconInterval uint16
	CapabilityInfo uint16
	AuthAlgorithm  uint16
	AuthSeq        uint16
	StatusCode     uint16
	ReasonCode     uint16
	AID            uint16
	ListenInterval uint16
	Elements       []Element
}

// RSN returns the parsed RSN element, if the frame carries one.
func (m *Management) RSN() (*RSNInfo, bool) {
	e, ok := Find(m.Elements, IERSN)
	if !ok {
		return nil, false
	}
	r, err := ParseRSN(e.Data)
	if err != nil {
		return nil, false
	}
	return r, true
}

// WPAVendorRSN returns the RSN-like body carried in the legacy WPA vendor
// specific element (Microsoft OUI, type 1).
func (m *Management) WPAVendorRSN() (*RSNInfo, bool) {
	for _, e := range m.Elements {
		if !e.Vendor || len(e.Data) < 4 {
			continue
		}
		if e.Data[0] == MSOUIIEEE[0] && e.Data[1] == MSOUIIEEE[1] && e.Data[2] == MSOUIIEEE[2] && e.Data[3] == 1 {
			r, err := ParseRSN(e.Data[4:])
			if err != nil {
				return nil, false
			}
			return r, true
		}
	}
	return nil, false
}

// ChannelOf returns the operating channel advertised by the frame.
func (m *Management) ChannelOf() int {
	if e, ok := Find(m.Elements, IEDSParameterSet); ok && len(e.Data) >= 1 {
		return int(e.Data[0])
	}
	return 0
}

// ChannelSwitch describes a Channel Switch Announcement element.
type ChannelSwitch struct {
	Channel    int
	Mode       uint8
	ReasonCode uint8
	Present    bool
}

// ParseManagement decodes the body of a management frame.
func ParseManagement(f *Frame) (*Management, error) {
	if f.Header.Type != TypeManagement {
		return nil, fmt.Errorf("dot11: not a management frame")
	}
	m := &Management{Kind: SubtypeName(f.Header.Subtype)}
	b := f.Body

	switch f.Header.Subtype {
	case MgmtBeacon, MgmtProbeResp:
		if len(b) < 12 {
			return m, fmt.Errorf("%w: beacon fixed parameters", ErrTruncated)
		}
		m.Timestamp = binary.LittleEndian.Uint64(b[0:8])
		m.BeaconInterval = binary.LittleEndian.Uint16(b[8:10])
		m.CapabilityInfo = binary.LittleEndian.Uint16(b[10:12])
		m.Elements = ParseElements(b[12:])
	case MgmtProbeReq:
		m.Elements = ParseElements(b)
	case MgmtAuth:
		if len(b) < 6 {
			return m, fmt.Errorf("%w: authentication fixed parameters", ErrTruncated)
		}
		m.AuthAlgorithm = binary.LittleEndian.Uint16(b[0:2])
		m.AuthSeq = binary.LittleEndian.Uint16(b[2:4])
		m.StatusCode = binary.LittleEndian.Uint16(b[4:6])
		m.Elements = ParseElements(b[6:])
	case MgmtAssocReq, MgmtReassocReq:
		if len(b) < 4 {
			return m, fmt.Errorf("%w: association fixed parameters", ErrTruncated)
		}
		m.CapabilityInfo = binary.LittleEndian.Uint16(b[0:2])
		m.ListenInterval = binary.LittleEndian.Uint16(b[2:4])
		m.Elements = ParseElements(b[4:])
	case MgmtAssocResp:
		if len(b) < 6 {
			return m, fmt.Errorf("%w: association response fixed parameters", ErrTruncated)
		}
		m.CapabilityInfo = binary.LittleEndian.Uint16(b[0:2])
		m.StatusCode = binary.LittleEndian.Uint16(b[2:4])
		m.AID = binary.LittleEndian.Uint16(b[4:6])
		m.Elements = ParseElements(b[6:])
	case MgmtDeauth, MgmtDisassoc:
		if len(b) < 2 {
			return m, fmt.Errorf("%w: reason code", ErrTruncated)
		}
		m.ReasonCode = binary.LittleEndian.Uint16(b[0:2])
		m.Elements = ParseElements(b[2:])
	case MgmtAction, MgmtActionNoAck:
		m.Elements = ParseElements(b)
	default:
		m.Elements = ParseElements(b)
	}
	return m, nil
}

// FormatMAC renders a hardware address, tolerating a nil address.
func FormatMAC(a net.HardwareAddr) string {
	if len(a) == 0 {
		return "-"
	}
	return a.String()
}
