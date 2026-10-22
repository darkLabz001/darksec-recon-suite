package eap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// eapol builds an 802.1X frame.
func eapol(version, typ uint16, body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(out[0:2], version)
	binary.BigEndian.PutUint16(out[2:4], typ)
	return append(out, body...)
}

// eapFrame builds an EAP frame.
func eapFrame(code, id uint8, typ uint8, data []byte) []byte {
	out := []byte{code, id, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(1+len(data)))
	if typ != 0 {
		out = append(out, typ)
	}
	return append(out, data...)
}

// eapolKey builds an EAPOL-Key frame.
func eapolKey(typ uint8, info uint16, keyData []byte) []byte {
	out := make([]byte, 0, 95+len(keyData))
	out = append(out, typ)
	out = binary.BigEndian.AppendUint16(out, info)
	out = binary.BigEndian.AppendUint16(out, 0) // the key data length follows
	out = binary.BigEndian.AppendUint64(out, 1) // the replay counter
	out = append(out, bytes.Repeat([]byte{0xAA}, 32)...)
	out = append(out, bytes.Repeat([]byte{0xBB}, 16)...)
	out = append(out, bytes.Repeat([]byte{0xCC}, 16)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keyData)))
	return append(out, keyData...)
}

func TestParseEAPOL(t *testing.T) {
	body := eapFrame(EAPCodeResponse, 7, EAPTypeIdentity, []byte("wyrm"))
	frame := eapol(2, EAPOLTypePacket, body)

	e, err := ParseEAPOL(frame)
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if e.Version != 2 {
		t.Errorf("the version reads %d, want 2", e.Version)
	}
	if e.Type != EAPOLTypePacket {
		t.Errorf("the type reads %d, want %d", e.Type, EAPOLTypePacket)
	}
	if e.Packet == nil {
		t.Fatal("the frame carries no EAP packet")
	}
	if e.Packet.Code != EAPCodeResponse {
		t.Errorf("the code reads %d, want %d", e.Packet.Code, EAPCodeResponse)
	}
	if e.Packet.ID != 7 {
		t.Errorf("the identifier reads %d, want 7", e.Packet.ID)
	}
	if e.Packet.Type != EAPTypeIdentity {
		t.Errorf("the type reads %d, want %d", e.Packet.Type, EAPTypeIdentity)
	}
	if e.Packet.Identity != "wyrm" {
		t.Errorf("the identity reads %q", e.Packet.Identity)
	}
}

func TestParseEAPOLRejectsShortFrames(t *testing.T) {
	if _, err := ParseEAPOL([]byte{0, 2, 0}); err == nil {
		t.Fatal("a short frame must be rejected")
	}
}

func TestParseEAPOLStart(t *testing.T) {
	e, err := ParseEAPOL(eapol(1, EAPOLTypeStart, nil))
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if e.Type != EAPOLTypeStart {
		t.Errorf("the type reads %d, want %d", e.Type, EAPOLTypeStart)
	}
	if e.Packet != nil || e.Key != nil {
		t.Error("the frame carries neither a packet nor a key")
	}
}

func TestParseEAPOLKey(t *testing.T) {
	keyData := []byte{0x01, 0x02, 0x03}
	frame := eapol(2, EAPOLTypeKey, eapolKey(KeyDescAESCCMP,
		KeyInfoKeyDescVer|KeyInfoPairwise|KeyInfoAck|KeyInfoMic|KeyInfoSecure, keyData))

	e, err := ParseEAPOL(frame)
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if e.Key == nil {
		t.Fatal("the frame carries no key")
	}
	if e.Key.DescriptorType != KeyDescAESCCMP {
		t.Errorf("the descriptor reads %d, want %d", e.Key.DescriptorType, KeyDescAESCCMP)
	}
	if e.Key.ReplayCounter != 1 {
		t.Errorf("the replay counter reads %d, want 1", e.Key.ReplayCounter)
	}
	if len(e.Key.Nonce) != 32 {
		t.Errorf("the nonce is %d bytes long, want 32", len(e.Key.Nonce))
	}
	if len(e.Key.IV) != 16 {
		t.Errorf("the vector is %d bytes long, want 16", len(e.Key.IV))
	}
	if len(e.Key.MIC) != 16 {
		t.Errorf("the key MIC is %d bytes long, want 16", len(e.Key.MIC))
	}
	if !bytes.Equal(e.Key.KeyData, keyData) {
		t.Errorf("the key data reads %x", e.Key.KeyData)
	}
	if !e.Key.IsPairwise() {
		t.Error("the key is a pairwise key")
	}
	if e.Key.KeyNumber() != 3 {
		t.Errorf("the key is message %d, want 3", e.Key.KeyNumber())
	}
}

func TestKeyNumber(t *testing.T) {
	cases := []struct {
		info uint16
		want int
	}{
		{0, 1},
		{KeyInfoMic, 2},
		{KeyInfoMic | KeyInfoAck, 3},
		{KeyInfoAck, 4},
	}
	for _, c := range cases {
		k := &EAPOLKey{Info: c.info}
		if got := k.KeyNumber(); got != c.want {
			t.Errorf("the key information %04x reads message %d, want %d", c.info, got, c.want)
		}
	}
}

func TestEAPTypeName(t *testing.T) {
	cases := map[uint8]string{
		EAPTypeIdentity: "Identity",
		EAPTypeTLS:      "EAP-TLS",
		EAPTypePWD:      "EAP-pwd",
	}
	for typ, want := range cases {
		if got := EAPTypeName(typ); got != want {
			t.Errorf("the type %d reads %q, want %q", typ, got, want)
		}
	}
	if got := EAPTypeName(200); got == "" {
		t.Error("an unknown type must still be rendered")
	}
}

func TestEAPOLKeyName(t *testing.T) {
	if got := EAPOLKeyName(KeyDescAESCCMP); got == "" {
		t.Error("the descriptor is not rendered")
	}
	if got := EAPOLKeyName(200); got == "" {
		t.Error("an unknown descriptor must still be rendered")
	}
}

func TestParseEAPWD(t *testing.T) {
	// A request of RFC 5216:
	//
	//	opcode 1, group 19, element length 32, element,
	//	password length 16, password, tag length 16, tag
	payload := []byte{EAPWDRequest}
	payload = binary.BigEndian.AppendUint16(payload, 19)
	payload = binary.BigEndian.AppendUint16(payload, 32)
	payload = append(payload, bytes.Repeat([]byte{0x01}, 32)...)
	payload = binary.BigEndian.AppendUint16(payload, 16)
	payload = append(payload, bytes.Repeat([]byte{0x02}, 16)...)
	payload = binary.BigEndian.AppendUint16(payload, 16)
	payload = append(payload, bytes.Repeat([]byte{0x03}, 16)...)

	w, err := ParseEAPWD(payload)
	if err != nil {
		t.Fatalf("the payload must parse: %v", err)
	}
	if w.Opcode != EAPWDRequest {
		t.Errorf("the opcode reads %d, want %d", w.Opcode, EAPWDRequest)
	}
	if w.OpcodeName() != "request" {
		t.Errorf("the opcode reads %q", w.OpcodeName())
	}
	if !w.HasGroup {
		t.Error("the payload carries a group")
	}
	if w.GroupID != 19 {
		t.Errorf("the group reads %d, want 19", w.GroupID)
	}
	if len(w.Element) != 32 {
		t.Errorf("the element is %d bytes long, want 32", len(w.Element))
	}
	if len(w.Password) != 16 {
		t.Errorf("the password is %d bytes long, want 16", len(w.Password))
	}
	if len(w.Tag) != 16 {
		t.Errorf("the tag is %d bytes long, want 16", len(w.Tag))
	}
}

func TestParseEAPWDResponse(t *testing.T) {
	payload := []byte{EAPWDResponse}
	payload = binary.BigEndian.AppendUint16(payload, 19)
	payload = binary.BigEndian.AppendUint16(payload, 0) // no element
	payload = binary.BigEndian.AppendUint16(payload, 0) // no password
	payload = binary.BigEndian.AppendUint16(payload, 4) // a value of four octets
	payload = append(payload, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)
	payload = binary.BigEndian.AppendUint16(payload, 0) // no tag

	w, err := ParseEAPWD(payload)
	if err != nil {
		t.Fatalf("the payload must parse: %v", err)
	}
	if w.OpcodeName() != "response" {
		t.Errorf("the opcode reads %q", w.OpcodeName())
	}
	if !bytes.Equal(w.Value, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("the value reads %x", w.Value)
	}
}

func TestParseEAPWDRejectsTruncatedPayloads(t *testing.T) {
	if _, err := ParseEAPWD(nil); err == nil {
		t.Fatal("an empty payload must be rejected")
	}
	if _, err := ParseEAPWD([]byte{EAPWDRequest, 0}); err == nil {
		t.Fatal("a payload without a group must be rejected")
	}
	if _, err := ParseEAPWD([]byte{EAPWDRequest, 0, 19, 0}); err == nil {
		t.Fatal("a payload without an element length must be rejected")
	}
	truncated := []byte{EAPWDRequest, 0, 19, 0, 32, 0x01}
	if _, err := ParseEAPWD(truncated); err == nil {
		t.Fatal("a truncated element must be rejected")
	}
}

func TestSameBytes(t *testing.T) {
	if !SameBytes([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("the two slices are the same")
	}
	if SameBytes([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("the two slices differ")
	}
	if SameBytes([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("the two slices have different lengths")
	}
	if !SameBytes(nil, nil) {
		t.Error("two empty slices are the same")
	}
}
