package dot11

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// ieee builds an IEEE OUI suite selector.
func ieee(t uint8) []byte { return []byte{0x00, 0x0F, 0xAC, t} }

// rsnElement builds the body of an RSN information element.
func rsnElement(group byte, pairwise []byte, akms []byte, caps uint16) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00}) // version
	b.Write(ieee(group))
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], uint16(len(pairwise)))
	b.Write(n[:])
	for _, c := range pairwise {
		b.Write(ieee(c))
	}
	binary.LittleEndian.PutUint16(n[:], uint16(len(akms)))
	b.Write(n[:])
	for _, a := range akms {
		b.Write(ieee(a))
	}
	binary.LittleEndian.PutUint16(n[:], caps)
	b.Write(n[:])
	return b.Bytes()
}

// element wraps a body in an information element header.
func element(id uint8, body []byte) []byte {
	return append([]byte{id, uint8(len(body))}, body...)
}

// beacon builds a beacon frame with the given information elements.
func beacon(bssid []byte, elements []byte) []byte {
	frame := make([]byte, 24)
	frame[0] = byte(MgmtBeacon<<4) | byte(TypeManagement<<2)
	frame[1] = 0
	copy(frame[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[10:16], bssid)
	copy(frame[16:22], bssid)

	body := make([]byte, 12, 12+len(elements))
	binary.LittleEndian.PutUint64(body[0:8], 0x1122334455667788)
	binary.LittleEndian.PutUint16(body[8:10], 100)
	binary.LittleEndian.PutUint16(body[10:12], 0x0411)
	body = append(body, elements...)

	return append(frame, body...)
}

func TestAKMSuiteTable(t *testing.T) {
	cases := []struct {
		typ      uint8
		name     string
		personal bool
		sae      bool
		owe      bool
		ent      bool
	}{
		{0x01, "802.1X", false, false, false, true},
		{0x02, "PSK", true, false, false, false},
		{0x08, "SAE", true, true, false, false},
		{0x09, "FT using SAE", true, true, false, false},
		{0x12, "OWE", false, false, true, false},
		{0x18, "SAE (group dependent)", true, true, false, false},
		{0x15, "PASN", false, false, false, false},
		{0x1D, "EPPKE", false, false, false, false},
	}
	for _, c := range cases {
		a := AKMSuite{OUI: IEEE80211OUI, Type: c.typ}
		if got := a.Name(); got != c.name {
			t.Errorf("the AKM type %02x reads %q, want %q", c.typ, got, c.name)
		}
		if a.IsPersonal() != c.personal {
			t.Errorf("the AKM type %02x personal is %v, want %v", c.typ, a.IsPersonal(), c.personal)
		}
		if a.IsSAE() != c.sae {
			t.Errorf("the AKM type %02x sae is %v, want %v", c.typ, a.IsSAE(), c.sae)
		}
		if a.IsOWE() != c.owe {
			t.Errorf("the AKM type %02x owe is %v, want %v", c.typ, a.IsOWE(), c.owe)
		}
		if a.IsEnterprise() != c.ent {
			t.Errorf("the AKM type %02x enterprise is %v, want %v", c.typ, a.IsEnterprise(), c.ent)
		}
	}
}

func TestAKMSuiteIsPSKFamily(t *testing.T) {
	psk := AKMSuite{OUI: IEEE80211OUI, Type: 0x02}
	sae := AKMSuite{OUI: IEEE80211OUI, Type: 0x08}
	ent := AKMSuite{OUI: IEEE80211OUI, Type: 0x01}
	if !psk.IsPSKFamily() {
		t.Error("the PSK suite is part of the PSK family")
	}
	if sae.IsPSKFamily() {
		t.Error("the SAE suite is not part of the PSK family")
	}
	if ent.IsPSKFamily() {
		t.Error("the 802.1X suite is not part of the PSK family")
	}
}

func TestAKMSuiteSelectorAndString(t *testing.T) {
	a := AKMSuite{OUI: IEEE80211OUI, Type: 0x08}
	if got := a.Selector(); got != [4]byte{0x00, 0x0F, 0xAC, 0x08} {
		t.Errorf("the selector reads %v", got)
	}
	if got := a.String(); got != "00-0f-ac:08" {
		t.Errorf("the suite reads %q", got)
	}
	if !a.IsIEEE() {
		t.Error("the suite uses the IEEE OUI")
	}
}

func TestCipherSuiteTable(t *testing.T) {
	cases := []struct {
		typ  uint8
		name string
		weak bool
	}{
		{0x01, "WEP (40-bit)", true},
		{0x02, "TKIP", true},
		{0x04, "AES (CCM)", false},
		{0x05, "WEP (104-bit)", true},
		{0x08, "GCMP (128)", false},
		{0x09, "GCMP (256)", false},
		{0x0A, "CCMP (256)", false},
	}
	for _, c := range cases {
		s := CipherSuite{OUI: IEEE80211OUI, Type: c.typ}
		if got := s.Name(); got != c.name {
			t.Errorf("the cipher type %02x reads %q, want %q", c.typ, got, c.name)
		}
		if s.IsWeak() != c.weak {
			t.Errorf("the cipher type %02x weak is %v, want %v", c.typ, s.IsWeak(), c.weak)
		}
	}
}

func TestParseRSNRejectsShortElements(t *testing.T) {
	if _, err := ParseRSN([]byte{0x01, 0x00, 0x00}); err == nil {
		t.Fatal("a short RSN element must be rejected")
	}
}

func TestParseRSN(t *testing.T) {
	body := rsnElement(0x04, []byte{0x04}, []byte{0x02}, RSNCapMFPC)
	r, err := ParseRSN(body)
	if err != nil {
		t.Fatalf("the RSN element must parse: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("the version is %d, want 1", r.Version)
	}
	if r.GroupCipher.Name() != "AES (CCM)" {
		t.Errorf("the group cipher reads %q", r.GroupCipher.Name())
	}
	if len(r.PairwiseCiphers) != 1 {
		t.Fatalf("the element carries %d pairwise ciphers, want 1", len(r.PairwiseCiphers))
	}
	if len(r.AKMs) != 1 {
		t.Fatalf("the element carries %d AKM suites, want 1", len(r.AKMs))
	}
	if !r.HasPSK() {
		t.Error("the element offers the PSK suite")
	}
	if r.HasSAE() {
		t.Error("the element does not offer the SAE suite")
	}
	if r.HasEnterprise() {
		t.Error("the element does not offer an 802.1X suite")
	}
	if !r.MFPC() {
		t.Error("the element is management frame protection capable")
	}
	if r.MFPR() {
		t.Error("the element does not require management frame protection")
	}
}

func TestParseRSNWithSAEAndPSK(t *testing.T) {
	// The WPA3 transition mode advertises both suites.
	body := rsnElement(0x04, []byte{0x04}, []byte{0x02, 0x08}, RSNCapMFPC|RSNCapMFPR)
	r, err := ParseRSN(body)
	if err != nil {
		t.Fatalf("the RSN element must parse: %v", err)
	}
	if !r.HasPSK() {
		t.Error("the element offers the PSK suite")
	}
	if !r.HasSAE() {
		t.Error("the element offers the SAE suite")
	}
	if !r.MFPR() {
		t.Error("the element requires management frame protection")
	}
	if !r.MFPC() {
		t.Error("the element is management frame protection capable")
	}
}

func TestParseRSNWithPMKIDs(t *testing.T) {
	body := rsnElement(0x04, []byte{0x04}, []byte{0x02}, 0)
	pmkid := bytes.Repeat([]byte{0xAB}, 16)
	body = append(body, 0x01, 0x00) // one PMKID
	body = append(body, pmkid...)
	body = append(body, ieee(0x04)...) // group management cipher

	r, err := ParseRSN(body)
	if err != nil {
		t.Fatalf("the RSN element must parse: %v", err)
	}
	if len(r.PMKIDs) != 1 {
		t.Fatalf("the element carries %d PMKIDs, want 1", len(r.PMKIDs))
	}
	if !bytes.Equal(r.PMKIDs[0], pmkid) {
		t.Error("the PMKID was not read correctly")
	}
	if r.GroupMgmtCipher == nil {
		t.Fatal("the group management cipher was not read")
	}
	if r.GroupMgmtCipher.Name() != "AES (CCM)" {
		t.Errorf("the group management cipher reads %q", r.GroupMgmtCipher.Name())
	}
}

func TestParseElements(t *testing.T) {
	blob := element(IESSID, []byte("wyrm"))
	blob = append(blob, element(IEDSParameterSet, []byte{0x06})...)

	els := ParseElements(blob)
	if len(els) != 2 {
		t.Fatalf("the blob carries %d elements, want 2", len(els))
	}
	if els[0].ID != IESSID {
		t.Errorf("the first element has the id %d, want %d", els[0].ID, IESSID)
	}
	if string(els[0].Data) != "wyrm" {
		t.Errorf("the SSID reads %q", els[0].Data)
	}
	if e, ok := Find(els, IEDSParameterSet); !ok {
		t.Error("the channel element was not found")
	} else if e.Data[0] != 6 {
		t.Errorf("the channel reads %d, want 6", e.Data[0])
	}
	if len(FindAll(els, IESSID)) != 1 {
		t.Error("the SSID element must be found once")
	}
}

func TestParseElementsKeepsATruncatedElement(t *testing.T) {
	els := ParseElements([]byte{IESSID, 10, 'a', 'b'})
	if len(els) != 1 {
		t.Fatalf("the blob carries %d elements, want 1", len(els))
	}
	if len(els[0].Data) != 2 {
		t.Errorf("the truncated element carries %d bytes, want 2", len(els[0].Data))
	}
}

func TestSSIDAndHiddenSSID(t *testing.T) {
	els := ParseElements(element(IESSID, []byte("home")))
	if got := SSIDOf(els); got != "home" {
		t.Errorf("the SSID reads %q, want %q", got, "home")
	}
	if HiddenSSID(els) {
		t.Error("the SSID is not hidden")
	}

	els = ParseElements(element(IESSID, nil))
	if got := SSIDOf(els); got != "" {
		t.Errorf("the SSID reads %q, want the empty string", got)
	}
	if !HiddenSSID(els) {
		t.Error("the SSID is hidden")
	}

	els = ParseElements(element(IERSN, []byte{0x01}))
	if HiddenSSID(els) {
		t.Error("a frame without an SSID element does not carry a hidden SSID")
	}
}

func TestExtCapBit(t *testing.T) {
	// Bit 88 is the SAE-PK exclusive bit, so it lives in the eleventh
	// octet.
	ext := make([]byte, 12)
	ext[11] = 1 << (88 % 8)
	if !ExtCapBit(ext, ExtCapSAEPKExclusively) {
		t.Error("the SAE-PK exclusive bit must be set")
	}
	if ExtCapBit(ext, ExtCapSAEPasswordsExclusiv) {
		t.Error("the SAE password exclusive bit must not be set")
	}
	if ExtCapBit(ext, 200) {
		t.Error("a bit outside the element must not be set")
	}
	if ExtCapBit([]byte{0x00}, ExtCapSAEPKExclusively) {
		t.Error("a bit outside the element must not be set")
	}
}

func TestRSNXESAEPK(t *testing.T) {
	// The first octet of the RSN extension element carries the length in
	// its low four bits and the flags in its high four bits.
	if !RSNXESAEPK([]byte{0x41}) {
		t.Error("the SAE-PK flag must be set")
	}
	if RSNXESAEPK([]byte{0x21}) {
		t.Error("the SAE-PK flag must not be set")
	}
	if RSNXESAEPK(nil) {
		t.Error("an empty element must not signal SAE-PK")
	}
}

func TestParseManagementBeacon(t *testing.T) {
	bssid := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	els := element(IESSID, []byte("wyrm-net"))
	els = append(els, element(IEDSParameterSet, []byte{0x0b})...)
	els = append(els, element(IERSN, rsnElement(0x04, []byte{0x04}, []byte{0x08}, RSNCapMFPC))...)

	f, err := Parse(beacon(bssid, els), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("the beacon must parse: %v", err)
	}
	if f.Header.Type != TypeManagement {
		t.Errorf("the frame type is %s, want management", f.Header.Type)
	}
	if f.Header.Subtype != MgmtBeacon {
		t.Errorf("the subtype is %d, want %d", f.Header.Subtype, MgmtBeacon)
	}
	if got := f.BSSID().String(); got != "02:11:22:33:44:55" {
		t.Errorf("the BSSID reads %q", got)
	}

	m, err := ParseManagement(f)
	if err != nil {
		t.Fatalf("the beacon must decode: %v", err)
	}
	if m.Kind != "beacon" {
		t.Errorf("the kind reads %q", m.Kind)
	}
	if m.BeaconInterval != 100 {
		t.Errorf("the beacon interval is %d, want 100", m.BeaconInterval)
	}
	if got := SSIDOf(m.Elements); got != "wyrm-net" {
		t.Errorf("the SSID reads %q", got)
	}
	if got := m.ChannelOf(); got != 11 {
		t.Errorf("the channel reads %d, want 11", got)
	}
	r, ok := m.RSN()
	if !ok {
		t.Fatal("the beacon carries no RSN element")
	}
	if !r.HasSAE() {
		t.Error("the beacon offers the SAE suite")
	}
	if r.HasPSK() {
		t.Error("the beacon does not offer the PSK suite")
	}
}

func TestParseManagementRejectsOtherFrames(t *testing.T) {
	frame := make([]byte, 24)
	frame[0] = byte(TypeData << 2)
	f, err := Parse(frame, time.Now())
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if _, err := ParseManagement(f); err == nil {
		t.Fatal("a data frame must not decode as a management frame")
	}
}

func TestParseRejectsTruncatedFrames(t *testing.T) {
	if _, err := Parse([]byte{1, 2, 3}, time.Now()); err == nil {
		t.Fatal("a short frame must be rejected")
	}
	if _, err := Parse(make([]byte, 20), time.Now()); err == nil {
		t.Fatal("a frame without a full MAC header must be rejected")
	}
}

func TestWPAVendorRSN(t *testing.T) {
	// The legacy WPA vendor specific element carries an RSN-like body
	// behind the Microsoft OUI and the type 1.
	body := append([]byte{0x00, 0x50, 0xF2, 0x01}, rsnElement(0x04, []byte{0x04}, []byte{0x02}, 0)...)
	els := element(IEVendorSpecific, body)

	f, err := Parse(beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, els), time.Now())
	if err != nil {
		t.Fatalf("the beacon must parse: %v", err)
	}
	m, err := ParseManagement(f)
	if err != nil {
		t.Fatalf("the beacon must decode: %v", err)
	}
	r, ok := m.WPAVendorRSN()
	if !ok {
		t.Fatal("the legacy WPA element was not found")
	}
	if !r.HasPSK() {
		t.Error("the legacy element offers the PSK suite")
	}
}

func TestVendorInfo(t *testing.T) {
	els := ParseElements(element(IEVendorSpecific, []byte{0x50, 0x6F, 0x9A, 0x1c, 0x00}))
	if len(els) != 1 {
		t.Fatal("the element was not parsed")
	}
	oui, subtype, ok := els[0].VendorInfo()
	if !ok {
		t.Fatal("the vendor information was not decoded")
	}
	if oui != WPA3OUI {
		t.Errorf("the OUI reads %v, want %v", oui, WPA3OUI)
	}
	if subtype != WFASubtypeOWETransitionMode {
		t.Errorf("the subtype reads %d, want %d", subtype, WFASubtypeOWETransitionMode)
	}
}

func TestFreqToChannel(t *testing.T) {
	cases := map[int]int{
		2412: 1,
		2437: 6,
		2472: 13,
		2484: 14,
		5180: 36,
		5745: 149,
		5955: 1,
	}
	for freq, want := range cases {
		if got := freqToChannel(freq); got != want {
			t.Errorf("the frequency %d reads channel %d, want %d", freq, got, want)
		}
	}
	if got := freqToChannel(1234); got != 0 {
		t.Errorf("an unknown frequency reads channel %d, want 0", got)
	}
}

func TestChannelToFreqAndBand(t *testing.T) {
	if got := ChannelToFreq(6, "2.4"); got != 2437 {
		t.Errorf("channel 6 reads %d MHz, want 2437", got)
	}
	if got := ChannelToFreq(14, "2.4"); got != 2484 {
		t.Errorf("channel 14 reads %d MHz, want 2484", got)
	}
	if got := ChannelToFreq(36, "5"); got != 5180 {
		t.Errorf("channel 36 reads %d MHz, want 5180", got)
	}
	if got := BandForFreq(2437); got != "2.4" {
		t.Errorf("2437 MHz is in the %q band, want 2.4", got)
	}
	if got := BandForFreq(5180); got != "5" {
		t.Errorf("5180 MHz is in the %q band, want 5", got)
	}
	if got := BandForFreq(6005); got != "6" {
		t.Errorf("6005 MHz is in the %q band, want 6", got)
	}
}
