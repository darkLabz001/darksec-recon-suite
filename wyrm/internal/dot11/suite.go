// Package dot11 parses IEEE 802.11 (Wi-Fi) management frames and the
// information elements that describe an access point's security posture.
//
// The suite selectors handled here follow IEEE 802.11-2020 Table 12-6: a
// selector is an OUI plus a one byte type. The IEEE OUI is 00-0F-AC. The
// tables below were cross-checked against Wireshark's
// ieee80211_rsn_keymgmt_vals and ieee80211_rsn_cipher_vals.
package dot11

import "fmt"

// IEEE80211OUI is the OUI used by the IEEE for the RSN cipher and AKM suite
// selectors (written 00-0F-AC in the literature).
var IEEE80211OUI = [3]byte{0x00, 0x0F, 0xAC}

// MSOUIIEEE is the Microsoft OUI (00-50-F2) used by the legacy WPA vendor
// specific information element.
var MSOUIIEEE = [3]byte{0x00, 0x50, 0xF2}

// WPA3OUI is the Wi-Fi Alliance OUI (50-6F-9A) used by the WPA3 transition
// mode and OWE transition mode vendor specific information elements.
var WPA3OUI = [3]byte{0x50, 0x6F, 0x9A}

// AKMSuite identifies an Authentication and Key Management suite.
type AKMSuite struct {
	OUI  [3]byte
	Type uint8
}

// Selector returns the four byte wire representation of the suite.
func (a AKMSuite) Selector() [4]byte {
	return [4]byte{a.OUI[0], a.OUI[1], a.OUI[2], a.Type}
}

// String renders the suite the way the literature writes it: "00-0F-AC:08".
func (a AKMSuite) String() string {
	return fmt.Sprintf("%02x-%02x-%02x:%02x", a.OUI[0], a.OUI[1], a.OUI[2], a.Type)
}

// IsIEEE reports whether the suite uses the IEEE OUI.
func (a AKMSuite) IsIEEE() bool { return a.OUI == IEEE80211OUI }

// akmInfo describes one AKM suite type.
type akmInfo struct {
	name string
	// personal is true for the per-password (PSK family) suites, which are
	// the ones that expose a password to offline attack.
	personal bool
	// sae is true for the Simultaneous Authentication of Equals suites
	// introduced by WPA3.
	sae bool
	// owe is true for Opportunistic Wireless Encryption.
	owe bool
	// enterprise is true for the 802.1X family.
	enterprise bool
}

// akmTable maps the IEEE AKM suite type byte to its meaning.
//
//	00-0F-AC:01 802.1X        00-0F-AC:08 SAE (WPA3)
//	00-0F-AC:02 PSK (WPA2)    00-0F-AC:09 FT-SAE
//	00-0F-AC:04 FT-PSK        00-0F-AC:12 OWE
//	00-0F-AC:0E FILS          00-0F-AC:18 SAE (group dependent)
var akmTable = map[uint8]akmInfo{
	0x00: {name: "NONE"},
	0x01: {name: "802.1X", enterprise: true},
	0x02: {name: "PSK", personal: true},
	0x03: {name: "FT over 802.1X", enterprise: true},
	0x04: {name: "FT using PSK", personal: true},
	0x05: {name: "802.1X (SHA256)", enterprise: true},
	0x06: {name: "PSK (SHA256)", personal: true},
	0x07: {name: "TDLS / TPK Handshake (SHA256)"},
	0x08: {name: "SAE", personal: true, sae: true},
	0x09: {name: "FT using SAE", personal: true, sae: true},
	0x0A: {name: "APPeerKey (SHA256)"},
	0x0B: {name: "802.1X (SHA256-SuiteB)", enterprise: true},
	0x0C: {name: "802.1X (SHA384-SuiteB)", enterprise: true},
	0x0D: {name: "FT over 802.1X (SHA384)", enterprise: true},
	0x0E: {name: "FILS (SHA256 and AES-SIV-256)"},
	0x0F: {name: "FILS (SHA384 and AES-SIV-512)"},
	0x10: {name: "FT over FILS (SHA256 and AES-SIV-256)"},
	0x11: {name: "FT over FILS (SHA384 and AES-SIV-512)"},
	0x12: {name: "OWE", owe: true},
	0x13: {name: "FT using PSK (SHA384)", personal: true},
	0x14: {name: "PSK (SHA384)", personal: true},
	0x15: {name: "PASN"},
	0x18: {name: "SAE (group dependent)", personal: true, sae: true},
	0x19: {name: "FT using SAE (group dependent)", personal: true, sae: true},
	0x1D: {name: "EPPKE"},
}

// Name returns a human readable name for the AKM suite.
func (a AKMSuite) Name() string {
	if a.IsIEEE() {
		if info, ok := akmTable[a.Type]; ok {
			return info.name
		}
		return fmt.Sprintf("unknown IEEE AKM type %02x", a.Type)
	}
	return fmt.Sprintf("vendor AKM %02x-%02x-%02x:%02x", a.OUI[0], a.OUI[1], a.OUI[2], a.Type)
}

// IsPersonal reports whether the suite authenticates with a shared password.
func (a AKMSuite) IsPersonal() bool { return a.IsIEEE() && akmTable[a.Type].personal }

// IsSAE reports whether the suite is SAE (Dragonfly).
func (a AKMSuite) IsSAE() bool { return a.IsIEEE() && akmTable[a.Type].sae }

// IsOWE reports whether the suite is OWE.
func (a AKMSuite) IsOWE() bool { return a.IsIEEE() && akmTable[a.Type].owe }

// IsEnterprise reports whether the suite is an 802.1X family suite.
func (a AKMSuite) IsEnterprise() bool { return a.IsIEEE() && akmTable[a.Type].enterprise }

// IsPSKFamily reports whether the suite is the WPA2 personal (PSK) family,
// i.e. the one whose handshake exposes the password to offline cracking.
func (a AKMSuite) IsPSKFamily() bool {
	return a.IsIEEE() && akmTable[a.Type].personal && !akmTable[a.Type].sae
}

// CipherSuite identifies a cipher suite selector.
type CipherSuite struct {
	OUI  [3]byte
	Type uint8
}

// Selector returns the four byte wire representation of the suite.
func (c CipherSuite) Selector() [4]byte {
	return [4]byte{c.OUI[0], c.OUI[1], c.OUI[2], c.Type}
}

// String renders the suite as "00-0F-AC:04".
func (c CipherSuite) String() string {
	return fmt.Sprintf("%02x-%02x-%02x:%02x", c.OUI[0], c.OUI[1], c.OUI[2], c.Type)
}

// IsIEEE reports whether the suite uses the IEEE OUI.
func (c CipherSuite) IsIEEE() bool { return c.OUI == IEEE80211OUI }

var cipherTable = map[uint8]string{
	0x00: "NONE",
	0x01: "WEP (40-bit)",
	0x02: "TKIP",
	0x03: "AES (OCB)",
	0x04: "AES (CCM)",
	0x05: "WEP (104-bit)",
	0x06: "BIP (128)",
	0x07: "group addressed traffic not allowed",
	0x08: "GCMP (128)",
	0x09: "GCMP (256)",
	0x0A: "CCMP (256)",
	0x0B: "BIP (GMAC-128)",
	0x0C: "BIP (GMAC-256)",
	0x0D: "BIP (CMAC-256)",
}

// Name returns a human readable name for the cipher suite.
func (c CipherSuite) Name() string {
	if c.IsIEEE() {
		if n, ok := cipherTable[c.Type]; ok {
			return n
		}
		return fmt.Sprintf("unknown IEEE cipher type %02x", c.Type)
	}
	return fmt.Sprintf("vendor cipher %02x-%02x-%02x:%02x", c.OUI[0], c.OUI[1], c.OUI[2], c.Type)
}

// IsWeak reports whether the cipher suite is one that should not be used.
func (c CipherSuite) IsWeak() bool {
	if !c.IsIEEE() {
		return true
	}
	switch c.Type {
	case 0x00, 0x01, 0x05, 0x02: // NONE, WEP-40, WEP-104, TKIP
		return true
	}
	return false
}
