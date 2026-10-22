// Package eap decodes the 802.1X encapsulation that carries EAP and
// EAPOL-Key traffic, and the EAP-pwd method of RFC 5216.
//
// The layouts implemented here follow IEEE 802.1X-2004 (EAPOL and EAPOL-Key)
// and RFC 5216 (EAP-pwd).
package eap

import (
	"encoding/binary"
	"fmt"
)

// EAPOL frame types.
const (
	EAPOLTypePacket uint16 = 0
	EAPOLTypeStart  uint16 = 1
	EAPOLTypeLogoff uint16 = 2
	EAPOLTypeKey    uint16 = 3
	EAPOLTypeASF    uint16 = 4
)

// EAP codes.
const (
	EAPCodeRequest  uint8 = 1
	EAPCodeResponse uint8 = 2
	EAPCodeSuccess  uint8 = 3
	EAPCodeFailure  uint8 = 4
)

// EAP types.
const (
	EAPTypeIdentity uint8 = 1
	EAPTypeNotify   uint8 = 2
	EAPTypeNAK      uint8 = 3
	EAPTypeMD5      uint8 = 4
	EAPTypeOTP      uint8 = 5
	EAPTypeGeneric  uint8 = 6
	EAPTypeTLS      uint8 = 13
	EAPTypeTTLS     uint8 = 21
	EAPTypePEAP     uint8 = 25
	EAPTypeMSCHAPv2 uint8 = 26
	EAPTypePWD      uint8 = 52
	EAPTypeOpennet  uint8 = 107
)

// EAPOL-Key descriptor types.
const (
	KeyDescRC4     uint8 = 1
	KeyDescTKIP    uint8 = 2
	KeyDescCCMP    uint8 = 3
	KeyDescWEP40   uint8 = 4
	KeyDescWEP104  uint8 = 5
	KeyDescBIP     uint8 = 6
	KeyDescWEP     uint8 = 7
	KeyDescTKIPRC4 uint8 = 8
	KeyDescAESCCMP uint8 = 9
	KeyDescWPA3    uint8 = 10
	KeyDescGCMP    uint8 = 11
)

// EAPOL-Key key information bits.
const (
	KeyInfoKeyDescMask   uint16 = 0x03
	KeyInfoKeyDescVer    uint16 = 0x3F00 // bits 8..9 in the shifted field
	KeyInfoPairwise      uint16 = 0x0008
	KeyInfoInstall       uint16 = 0x0040
	KeyInfoAck           uint16 = 0x0080
	KeyInfoMic           uint16 = 0x0100
	KeyInfoSecure        uint16 = 0x0200
	KeyInfoEncrypted     uint16 = 0x0400
	KeyInfoRequest       uint16 = 0x0800
	KeyInfoEncryptedData uint16 = 0x2000
)

// EAPOL is a decoded 802.1X frame.
type EAPOL struct {
	Version uint16
	Type    uint16
	Length  int
	Raw     []byte

	// Exactly one of the following is set.
	Packet *EAP
	Key    *EAPOLKey
}

// EAP is a decoded EAP frame.
type EAP struct {
	Code     uint8
	ID       uint8
	Length   int
	Type     uint8
	HasType  bool
	Data     []byte
	Identity string
}

// EAPOLKey is a decoded EAPOL-Key frame.
type EAPOLKey struct {
	DescriptorType uint8
	Info           uint16
	Length         int
	ReplayCounter  uint64
	Nonce          []byte
	IV             []byte
	MIC            []byte
	KeyDataLen     int
	KeyData        []byte
}

// KeyNumber returns the EAPOL-Key message number, 1 to 4.
func (k *EAPOLKey) KeyNumber() int {
	switch {
	case k.Info&KeyInfoAck == 0 && k.Info&KeyInfoMic == 0:
		return 1
	case k.Info&KeyInfoMic != 0 && k.Info&KeyInfoAck == 0:
		return 2
	case k.Info&KeyInfoMic != 0 && k.Info&KeyInfoAck != 0:
		return 3
	case k.Info&KeyInfoMic == 0:
		return 4
	}
	return 0
}

// IsPairwise reports whether the key is a pairwise (unicast) key.
func (k *EAPOLKey) IsPairwise() bool { return k.Info&KeyInfoPairwise != 0 }

// EAPOLKeyName renders the key descriptor type.
func EAPOLKeyName(t uint8) string {
	switch t {
	case KeyDescRC4:
		return "RC4"
	case KeyDescTKIP:
		return "TKIP"
	case KeyDescCCMP:
		return "CCMP"
	case KeyDescWEP40:
		return "WEP 40-bit"
	case KeyDescWEP104:
		return "WEP 104-bit"
	case KeyDescBIP:
		return "BIP"
	case KeyDescWEP:
		return "WEP"
	case KeyDescTKIPRC4:
		return "TKIP with RC4"
	case KeyDescAESCCMP:
		return "AES-CCMP"
	case KeyDescWPA3:
		return "WPA3"
	case KeyDescGCMP:
		return "GCMP"
	}
	return fmt.Sprintf("descriptor %d", t)
}

// EAPTypeName renders an EAP type.
func EAPTypeName(t uint8) string {
	switch t {
	case EAPTypeIdentity:
		return "Identity"
	case EAPTypeNotify:
		return "Notification"
	case EAPTypeNAK:
		return "NAK"
	case EAPTypeMD5:
		return "MD5-Challenge"
	case EAPTypeOTP:
		return "One-Time Password"
	case EAPTypeGeneric:
		return "Generic"
	case EAPTypeTLS:
		return "EAP-TLS"
	case EAPTypeTTLS:
		return "EAP-TTLS"
	case EAPTypePEAP:
		return "PEAP"
	case EAPTypeMSCHAPv2:
		return "EAP-MSCHAPv2"
	case EAPTypePWD:
		return "EAP-pwd"
	case EAPTypeOpennet:
		return "Open Network"
	}
	return fmt.Sprintf("type %d", t)
}

// ParseEAPOL decodes an 802.1X frame.
func ParseEAPOL(data []byte) (*EAPOL, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("eap: EAPOL frame too short (%d bytes)", len(data))
	}
	e := &EAPOL{
		Version: binary.BigEndian.Uint16(data[0:2]),
		Type:    binary.BigEndian.Uint16(data[2:4]),
		Raw:     append([]byte(nil), data...),
	}
	if len(data) >= 6 {
		e.Length = int(binary.BigEndian.Uint16(data[4:6]))
	}
	body := data[4:]
	switch e.Type {
	case EAPOLTypePacket:
		p, err := ParseEAP(body)
		if err != nil {
			return e, err
		}
		e.Packet = p
	case EAPOLTypeKey:
		k, err := ParseEAPOLKey(body)
		if err != nil {
			return e, err
		}
		e.Key = k
	}
	return e, nil
}

// ParseEAP decodes an EAP frame.
func ParseEAP(data []byte) (*EAP, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("eap: EAP frame too short (%d bytes)", len(data))
	}
	p := &EAP{
		Code:   data[0],
		ID:     data[1],
		Length: int(binary.BigEndian.Uint16(data[2:4])),
	}
	if len(data) >= 5 {
		p.HasType = true
		p.Type = data[4]
		p.Data = append([]byte(nil), data[5:]...)
		if p.Type == EAPTypeIdentity {
			p.Identity = string(data[5:])
		}
	} else {
		p.Data = nil
	}
	return p, nil
}

// ParseEAPOLKey decodes an EAPOL-Key frame.
func ParseEAPOLKey(data []byte) (*EAPOLKey, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("eap: EAPOL-Key frame too short (%d bytes)", len(data))
	}
	k := &EAPOLKey{
		DescriptorType: data[0],
		Info:           binary.BigEndian.Uint16(data[1:3]),
		Length:         int(binary.BigEndian.Uint16(data[3:5])),
	}
	p := 5
	if len(data) < p+8 {
		return k, fmt.Errorf("eap: EAPOL-Key frame has no replay counter")
	}
	k.ReplayCounter = binary.BigEndian.Uint64(data[p : p+8])
	p += 8
	if len(data) < p+32 {
		return k, fmt.Errorf("eap: EAPOL-Key frame has no nonce")
	}
	k.Nonce = append([]byte(nil), data[p:p+32]...)
	p += 32
	if len(data) < p+16 {
		return k, fmt.Errorf("eap: EAPOL-Key frame has no IV")
	}
	k.IV = append([]byte(nil), data[p:p+16]...)
	p += 16
	if len(data) < p+16 {
		return k, fmt.Errorf("eap: EAPOL-Key frame has no key MIC")
	}
	k.MIC = append([]byte(nil), data[p:p+16]...)
	p += 16
	if len(data) < p+2 {
		return k, fmt.Errorf("eap: EAPOL-Key frame has no key data length")
	}
	k.KeyDataLen = int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if len(data) < p+k.KeyDataLen {
		return k, fmt.Errorf("eap: EAPOL-Key key data is truncated")
	}
	k.KeyData = append([]byte(nil), data[p:p+k.KeyDataLen]...)
	return k, nil
}
