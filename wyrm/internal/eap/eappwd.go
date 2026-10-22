package eap

import (
	"encoding/binary"
	"fmt"
)

// EAP-pwd opcodes from RFC 5216 section 2.4.
const (
	EAPWDRequest  uint8 = 1
	EAPWDResponse uint8 = 2
	EAPWDSuccess  uint8 = 3
	EAPWDFailure  uint8 = 4
)

// EAPWD is a decoded EAP-pwd payload.
//
// The layout follows RFC 5216 section 2.4:
//
//	Opcode          1 octet
//	Group ID        2 octets
//	Element Length  2 octets
//	Element         Element Length octets
//	Password Length 2 octets
//	Password        Password Length octets
//	Value Length    2 octets, responses only
//	Value           Value Length octets, responses only
//	Tag Length      2 octets
//	Tag             Tag Length octets
type EAPWD struct {
	Opcode   uint8
	GroupID  uint16
	HasGroup bool
	Element  []byte
	Password []byte
	Value    []byte
	Tag      []byte
}

// OpcodeName renders the EAP-pwd opcode.
func (w *EAPWD) OpcodeName() string {
	switch w.Opcode {
	case EAPWDRequest:
		return "request"
	case EAPWDResponse:
		return "response"
	case EAPWDSuccess:
		return "success"
	case EAPWDFailure:
		return "failure"
	}
	return fmt.Sprintf("opcode %d", w.Opcode)
}

// ParseEAPWD decodes an EAP-pwd payload.
func ParseEAPWD(data []byte) (*EAPWD, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("eap: EAP-pwd payload is empty")
	}
	w := &EAPWD{Opcode: data[0]}
	p := 1

	if p+2 > len(data) {
		return w, fmt.Errorf("eap: EAP-pwd payload has no group identifier")
	}
	w.GroupID = binary.BigEndian.Uint16(data[p : p+2])
	w.HasGroup = true
	p += 2

	if p+2 > len(data) {
		return w, fmt.Errorf("eap: EAP-pwd payload has no element length")
	}
	n := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if p+n > len(data) {
		return w, fmt.Errorf("eap: EAP-pwd element is truncated")
	}
	w.Element = append([]byte(nil), data[p:p+n]...)
	p += n

	if p+2 > len(data) {
		return w, fmt.Errorf("eap: EAP-pwd payload has no password length")
	}
	n = int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if p+n > len(data) {
		return w, fmt.Errorf("eap: EAP-pwd password is truncated")
	}
	w.Password = append([]byte(nil), data[p:p+n]...)
	p += n

	if w.Opcode == EAPWDResponse {
		if p+2 > len(data) {
			return w, fmt.Errorf("eap: EAP-pwd response has no value length")
		}
		n = int(binary.BigEndian.Uint16(data[p : p+2]))
		p += 2
		if p+n > len(data) {
			return w, fmt.Errorf("eap: EAP-pwd value is truncated")
		}
		w.Value = append([]byte(nil), data[p:p+n]...)
		p += n
	}

	if p+2 > len(data) {
		return w, nil
	}
	n = int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if p+n > len(data) {
		return w, fmt.Errorf("eap: EAP-pwd tag is truncated")
	}
	w.Tag = append([]byte(nil), data[p:p+n]...)

	return w, nil
}

// SameBytes reports whether two byte slices are identical.
func SameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
