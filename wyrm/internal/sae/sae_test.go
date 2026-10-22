package sae

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"
)

// buildAuth lays out an authentication frame body the way hostapd does.
//
//	Authentication Algorithm   2 octets
//	Authentication Sequence   2 octets
//	Status Code               2 octets
//	Payload                   variable
func buildAuth(alg, seq, status uint16, payload []byte) []byte {
	body := make([]byte, 6, 6+len(payload))
	binary.LittleEndian.PutUint16(body[0:2], alg)
	binary.LittleEndian.PutUint16(body[2:4], seq)
	binary.LittleEndian.PutUint16(body[4:6], status)
	return append(body, payload...)
}

// buildCommit lays out the payload of a commit message:
//
//	Finite Cyclic Group   2 octets
//	Anti-Clogging Token   variable
//	commit-scalar         FieldLen octets
//	commit-element        FieldLen or 2*FieldLen octets
func buildCommit(groupID uint16, token, scalar, element []byte) []byte {
	payload := make([]byte, 2, 2+len(token)+len(scalar)+len(element))
	binary.LittleEndian.PutUint16(payload[0:2], groupID)
	payload = append(payload, token...)
	payload = append(payload, scalar...)
	payload = append(payload, element...)
	return payload
}

// buildConfirm lays out the payload of a confirm message:
//
//	Send-Confirm       2 octets
//	commit-scalar      FieldLen octets
//	commit-element     FieldLen or 2*FieldLen octets
//	Confirm Tag        HashLen octets
func buildConfirm(sendConfirm uint16, scalar, element, tag []byte) []byte {
	payload := make([]byte, 2, 2+len(scalar)+len(element)+len(tag))
	binary.LittleEndian.PutUint16(payload[0:2], sendConfirm)
	payload = append(payload, scalar...)
	payload = append(payload, element...)
	payload = append(payload, tag...)
	return payload
}

// generator builds a valid scalar and element for the given group.
func generator(t *testing.T, g *Group) (scalar, element []byte) {
	t.Helper()
	switch g.Kind {
	case KindECC:
		element = make([]byte, g.ElementLen())
		g.ECC.Gx.FillBytes(element[:g.FieldLen])
		g.ECC.Gy.FillBytes(element[g.FieldLen:])
	default:
		element = make([]byte, g.ElementLen())
		element[g.FieldLen-1] = 2
	}
	scalar = make([]byte, g.FieldLen)
	scalar[g.FieldLen-1] = 3
	return scalar, element
}

func TestParseAuthRejectsShortFrames(t *testing.T) {
	if _, err := ParseAuth([]byte{3, 0}); err == nil {
		t.Fatal("a short frame must be rejected")
	}
}

func TestParseAuthRejectsOtherAlgorithms(t *testing.T) {
	body := buildAuth(0, SeqCommit, StatusSuccess, nil)
	if _, err := ParseAuth(body); err == nil {
		t.Fatal("an authentication frame that is not SAE must be rejected")
	}
}

func TestParseCommitWithoutAToken(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	scalar, element := generator(t, g)

	body := buildAuth(AuthAlgorithmSAE, SeqCommit, StatusSuccess,
		buildCommit(g.ID, nil, scalar, element))

	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the commit must parse: %v", err)
	}
	if !m.IsCommit() {
		t.Error("the message must be a commit")
	}
	if m.Algorithm != AuthAlgorithmSAE {
		t.Errorf("the algorithm is %d, want %d", m.Algorithm, AuthAlgorithmSAE)
	}
	if m.GroupID != g.ID {
		t.Errorf("the group is %d, want %d", m.GroupID, g.ID)
	}
	if m.Group == nil {
		t.Fatal("the group was not resolved")
	}
	if len(m.AntiClog) != 0 {
		t.Errorf("a commit without a token carried %d token bytes", len(m.AntiClog))
	}
	if !bytes.Equal(m.Scalar, scalar) {
		t.Error("the commit scalar was not read correctly")
	}
	if !bytes.Equal(m.Element, element) {
		t.Error("the commit element was not read correctly")
	}
	if m.StatusName() != "success" {
		t.Errorf("the status reads %q, want %q", m.StatusName(), "success")
	}
}

// The anti-clogging token precedes the commit scalar.  hostapd's
// sae_write_commit and Wireshark's add_ff_auth_sae agree on that layout,
// so the auditor has to follow it.
func TestParseCommitPutsTheTokenBeforeTheScalar(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	scalar, element := generator(t, g)
	token := bytes.Repeat([]byte{0xAB}, 16)

	body := buildAuth(AuthAlgorithmSAE, SeqCommit, StatusSuccess,
		buildCommit(g.ID, token, scalar, element))

	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the commit must parse: %v", err)
	}
	if !bytes.Equal(m.AntiClog, token) {
		t.Errorf("the token reads %x, want %x", m.AntiClog, token)
	}
	if !bytes.Equal(m.Scalar, scalar) {
		t.Error("the commit scalar was not read correctly")
	}
	if !bytes.Equal(m.Element, element) {
		t.Error("the commit element was not read correctly")
	}
}

func TestParseCommitWithAStatusThatAsksForAToken(t *testing.T) {
	// A frame with status 76 is short: the finite cyclic group is still
	// present, but the fixed field carries only the anti-clogging token
	// that the peer asks for.
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	token := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 8)

	payload := make([]byte, 2, 2+len(token))
	binary.LittleEndian.PutUint16(payload[0:2], g.ID)
	payload = append(payload, token...)

	body := buildAuth(AuthAlgorithmSAE, SeqCommit, StatusAntiCloggingTokenRequired, payload)

	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the commit must parse: %v", err)
	}
	if m.Status != StatusAntiCloggingTokenRequired {
		t.Errorf("the status is %d, want %d", m.Status, StatusAntiCloggingTokenRequired)
	}
	if m.GroupID != g.ID {
		t.Errorf("the group is %d, want %d", m.GroupID, g.ID)
	}
	if !bytes.Equal(m.AntiClog, token) {
		t.Errorf("the token reads %x, want %x", m.AntiClog, token)
	}
	if len(m.Scalar) != 0 {
		t.Errorf("the frame carries a %d byte scalar, want none", len(m.Scalar))
	}
	if m.StatusName() != "anti-clogging token required" {
		t.Errorf("the status reads %q", m.StatusName())
	}
}

func TestParseCommitWithAGroupThatIsNotSupported(t *testing.T) {
	// Status 77 carries the finite cyclic group and the rejected groups
	// element instead of a scalar and an element.
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	rejected := []byte{0xff, 0x03, ExtIDRejectedGroups, 0x00, 0x13}

	payload := make([]byte, 2, 2+len(rejected))
	binary.LittleEndian.PutUint16(payload[0:2], g.ID)
	payload = append(payload, rejected...)

	body := buildAuth(AuthAlgorithmSAE, SeqCommit, StatusFiniteCyclicGroupNotSupport, payload)

	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the commit must parse: %v", err)
	}
	if m.Status != StatusFiniteCyclicGroupNotSupport {
		t.Errorf("the status is %d, want %d", m.Status, StatusFiniteCyclicGroupNotSupport)
	}
	if m.GroupID != g.ID {
		t.Errorf("the group is %d, want %d", m.GroupID, g.ID)
	}
	if len(m.Scalar) != 0 {
		t.Errorf("the frame carries a %d byte scalar, want none", len(m.Scalar))
	}
	if len(m.Elements) != 1 {
		t.Fatalf("the frame carries %d extension elements, want 1", len(m.Elements))
	}
	if m.Elements[0].ID != ExtIDRejectedGroups {
		t.Errorf("the extension element has the id %d, want %d", m.Elements[0].ID, ExtIDRejectedGroups)
	}
}

func TestParseCommitWithTrailingExtensionElements(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	scalar, element := generator(t, g)

	payload := buildCommit(g.ID, nil, scalar, element)
	// The rejected groups element: 0xff, length, id, data.
	payload = append(payload, 0xff, 0x03, ExtIDRejectedGroups, 0x00, 0x13)

	body := buildAuth(AuthAlgorithmSAE, SeqCommit, StatusSuccess, payload)
	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the commit must parse: %v", err)
	}
	if !bytes.Equal(m.Scalar, scalar) {
		t.Error("the commit scalar was not read correctly")
	}
	if !bytes.Equal(m.Element, element) {
		t.Error("the commit element was not read correctly")
	}
	if len(m.Elements) != 1 {
		t.Fatalf("the frame carries %d extension elements, want 1", len(m.Elements))
	}
	if m.Elements[0].ID != ExtIDRejectedGroups {
		t.Errorf("the extension element has the id %d, want %d", m.Elements[0].ID, ExtIDRejectedGroups)
	}
}

func TestParseCommitWithAnUnknownGroup(t *testing.T) {
	body := buildAuth(AuthAlgorithmSAE, SeqCommit, StatusSuccess,
		buildCommit(4242, nil, make([]byte, 32), make([]byte, 64)))

	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the commit must parse: %v", err)
	}
	if m.Group != nil {
		t.Error("an unknown group must not be resolved")
	}
	if m.GroupID != 4242 {
		t.Errorf("the group is %d, want 4242", m.GroupID)
	}
}

func TestParseConfirm(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	scalar, element := generator(t, g)
	tag := bytes.Repeat([]byte{0x5A}, g.TagLen())

	body := buildAuth(AuthAlgorithmSAE, SeqConfirm, StatusSuccess,
		buildConfirm(1, scalar, element, tag))

	m, err := ParseAuth(body)
	if err != nil {
		t.Fatalf("the confirm must parse: %v", err)
	}
	if !m.IsConfirm() {
		t.Error("the message must be a confirm")
	}
	if m.SendConfirm != 1 {
		t.Errorf("the send-confirm counter is %d, want 1", m.SendConfirm)
	}
	if err := m.DecodeConfirm(g); err != nil {
		t.Fatalf("the confirm must decode: %v", err)
	}
	if !bytes.Equal(m.Scalar, scalar) {
		t.Error("the commit scalar was not read correctly")
	}
	if !bytes.Equal(m.Element, element) {
		t.Error("the commit element was not read correctly")
	}
	if !bytes.Equal(m.Tag, tag) {
		t.Error("the confirm tag was not read correctly")
	}
}

func TestDecodeConfirmNeedsAGroup(t *testing.T) {
	m := &Message{}
	if err := m.DecodeConfirm(nil); err == nil {
		t.Fatal("a confirm cannot be decoded without a group")
	}
}

func TestDecodeConfirmRejectsAShortFrame(t *testing.T) {
	g, _ := GroupByID(19)
	m := &Message{Payload: []byte{1, 0, 2, 3}}
	if err := m.DecodeConfirm(g); err == nil {
		t.Fatal("a short confirm must be rejected")
	}
}

func TestValidateCommitAcceptsAGoodCommit(t *testing.T) {
	g, _ := GroupByID(19)
	scalar, element := generator(t, g)

	v := ValidateCommit(g, scalar, element)
	if !v.Valid {
		t.Fatalf("the commit must pass validation: %s", v.Summary)
	}
	if v.Failed != 0 {
		t.Errorf("the commit failed %d checks", v.Failed)
	}
}

func TestValidateCommitRejectsAScalarOutOfRange(t *testing.T) {
	g, _ := GroupByID(19)
	_, element := generator(t, g)

	scalar := make([]byte, g.FieldLen)
	// A scalar that is larger than p-1 must be rejected.
	new(big.Int).Add(g.ECC.P, big.NewInt(1)).FillBytes(scalar)

	v := ValidateCommit(g, scalar, element)
	if v.Valid {
		t.Fatal("a scalar that is out of range must not pass validation")
	}
	if v.WorstSeverity() != SeverityCritical {
		t.Errorf("the worst severity is %q, want %q", v.WorstSeverity(), SeverityCritical)
	}
}

func TestValidateCommitRejectsAnUnknownGroup(t *testing.T) {
	v := ValidateCommit(nil, nil, nil)
	if v.Valid {
		t.Fatal("an unknown group must not pass validation")
	}
}
