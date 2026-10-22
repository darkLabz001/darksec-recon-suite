package sae

import (
	"encoding/binary"
	"fmt"
)

// Extension element identifiers that may trail a SAE message.  The values
// come from hostapd's src/common/ieee802_11_defs.h.
const (
	ExtIDPasswordIdentifier uint8 = 33
	ExtIDRejectedGroups     uint8 = 92
	ExtIDAntiCloggingToken  uint8 = 93
	ExtIDMultiLink          uint8 = 107
	ExtIDAKMSuiteSelector   uint8 = 114
)

// ExtElement is one trailing extension element of a SAE message.
type ExtElement struct {
	ID   uint8
	Data []byte
}

// Message is a decoded SAE authentication frame.
type Message struct {
	Algorithm uint16
	Sequence  uint16
	Status    uint16

	GroupID uint16
	Group   *Group

	// AntiClog holds the anti-clogging token when the peer sent one.
	AntiClog []byte
	// Scalar and Element hold the commit scalar and commit element.
	Scalar  []byte
	Element []byte

	// SendConfirm is the counter of a confirm message.
	SendConfirm uint16
	// Tag is the confirm tag.
	Tag []byte

	// Elements are the trailing extension elements.
	Elements []ExtElement

	// Payload is the frame body after the fixed authentication parameters.
	Payload []byte
}

// IsCommit reports whether the frame carries a commit message.
func (m *Message) IsCommit() bool { return m.Sequence == SeqCommit }

// IsConfirm reports whether the frame carries a confirm message.
func (m *Message) IsConfirm() bool { return m.Sequence == SeqConfirm }

// StatusName renders the status code of the frame.
func (m *Message) StatusName() string {
	switch m.Status {
	case StatusSuccess:
		return "success"
	case StatusUnspecifiedFailure:
		return "unspecified failure"
	case StatusAntiCloggingTokenRequired:
		return "anti-clogging token required"
	case StatusFiniteCyclicGroupNotSupport:
		return "finite cyclic group not supported"
	}
	return fmt.Sprintf("status %d", m.Status)
}

// ParseAuth decodes the body of an 802.11 authentication frame that carries
// an SAE message.
func ParseAuth(body []byte) (*Message, error) {
	if len(body) < 6 {
		return nil, fmt.Errorf("sae: authentication frame too short (%d bytes)", len(body))
	}
	m := &Message{
		Algorithm: binary.LittleEndian.Uint16(body[0:2]),
		Sequence:  binary.LittleEndian.Uint16(body[2:4]),
		Status:    binary.LittleEndian.Uint16(body[4:6]),
		Payload:   append([]byte(nil), body[6:]...),
	}
	if m.Algorithm != AuthAlgorithmSAE {
		return nil, fmt.Errorf("sae: authentication algorithm %d is not SAE", m.Algorithm)
	}
	switch m.Sequence {
	case SeqCommit:
		m.parseCommit()
	case SeqConfirm:
		m.parseConfirm()
	default:
		return m, fmt.Errorf("sae: unknown authentication sequence %d", m.Sequence)
	}
	return m, nil
}

// parseCommit decodes a commit message.
//
// The commit payload is
//
//	Finite Cyclic Group   2 octets
//	Anti-Clogging Token   variable
//	commit-scalar         FieldLen octets
//	commit-element        FieldLen (FFC) or 2*FieldLen (ECC) octets
//
// The anti-clogging token precedes the scalar, which is how both hostapd
// (sae_write_commit) and Wireshark (add_ff_auth_sae) lay the frame out.
//
// The finite cyclic group, the anti-clogging token, the scalar and the
// element are present for the status codes success, anti-clogging token
// required, finite cyclic group not supported and hash to element only.  The
// scalar and the element are present for the success and the hash to element
// status codes only, which is what the dissector does as well.
func (m *Message) parseCommit() {
	if len(m.Payload) < 2 {
		return
	}
	m.GroupID = binary.LittleEndian.Uint16(m.Payload[0:2])
	g, ok := GroupByID(m.GroupID)
	if !ok {
		return
	}
	m.Group = g
	rest := m.Payload[2:]

	switch m.Status {
	case StatusSuccess, StatusAntiCloggingTokenRequired,
		StatusFiniteCyclicGroupNotSupport, StatusSAEHashToElement:
	default:
		return
	}

	if m.Status == StatusFiniteCyclicGroupNotSupport {
		// The peer refused the group, so the frame carries the rejected
		// groups element and neither a scalar nor an element.
		m.Elements = parseExtElements(rest)
		return
	}

	fixed := rest[:findFixedFieldLen(rest)]
	need := g.FieldLen + g.ElementLen()

	// The anti-clogging token comes before the scalar.  It is present
	// when the fixed field is longer than the scalar and the element
	// together, and also when the peer asks for a token with a frame that
	// carries nothing else.
	hasToken := (m.Status == StatusAntiCloggingTokenRequired || m.Status == StatusSAEHashToElement) && len(fixed) > need
	hasToken = hasToken || (m.Status == StatusAntiCloggingTokenRequired && len(fixed) > 0 && len(fixed) < need)
	hasToken = hasToken || (m.Status == StatusSuccess && len(fixed) > need)
	if hasToken {
		tokenLen := len(fixed) - need
		if tokenLen < 0 {
			tokenLen = len(fixed)
		}
		m.AntiClog = append([]byte(nil), fixed[:tokenLen]...)
		fixed = fixed[tokenLen:]
	}

	// The scalar and the element are only present in a successful commit
	// and in a hash to element commit.
	if m.Status == StatusSuccess || m.Status == StatusSAEHashToElement {
		if len(fixed) >= need {
			m.Scalar = append([]byte(nil), fixed[:g.FieldLen]...)
			m.Element = append([]byte(nil), fixed[g.FieldLen:need]...)
		}
	}

	m.Elements = parseExtElements(rest[findFixedFieldLen(rest):])
}

// parseConfirm decodes the parts of a confirm message that do not depend on
// the negotiated group.
func (m *Message) parseConfirm() {
	if len(m.Payload) < 2 {
		return
	}
	m.SendConfirm = binary.LittleEndian.Uint16(m.Payload[0:2])
	// The trailing extension elements start after the fixed field, which
	// is measured from the end of the send-confirm counter.
	m.Elements = parseExtElements(m.Payload[2+findFixedFieldLen(m.Payload[2:]):])
}

// DecodeConfirm splits a confirm message into its scalar, element and tag
// using the group that was negotiated during the matching commit.  A confirm
// message does not carry the group identifier itself.
func (m *Message) DecodeConfirm(g *Group) error {
	if g == nil {
		return fmt.Errorf("sae: cannot decode a confirm message without a group")
	}
	if len(m.Payload) < 2 {
		return fmt.Errorf("sae: confirm message is too short")
	}
	body := m.Payload[2:]
	body = body[:findFixedFieldLen(body)]
	need := g.FieldLen + g.ElementLen() + g.TagLen()
	if len(body) < need {
		return fmt.Errorf("sae: confirm message is too short for %s (%d of %d bytes)",
			g.Name, len(body), need)
	}
	m.Scalar = append([]byte(nil), body[:g.FieldLen]...)
	m.Element = append([]byte(nil), body[g.FieldLen:g.FieldLen+g.ElementLen()]...)
	m.Tag = append([]byte(nil), body[g.FieldLen+g.ElementLen():need]...)
	return nil
}

// findFixedFieldLen returns the length of the fixed part of a SAE payload,
// that is everything up to the first trailing extension element.  The rule
// mirrors Wireshark's find_fixed_field_len: an extension element starts with
// the 0xff tag and is only recognised once the fixed field is long enough to
// hold at least a 32 octet scalar.
func findFixedFieldLen(b []byte) int {
	for off := 0; off < len(b); off++ {
		if b[off] != 0xff {
			continue
		}
		if off < 32 {
			continue
		}
		if off > len(b)-4 {
			continue
		}
		switch b[off+2] {
		case ExtIDRejectedGroups, ExtIDPasswordIdentifier, ExtIDAntiCloggingToken,
			ExtIDMultiLink, ExtIDAKMSuiteSelector:
			if off+int(b[off+1])+2 <= len(b) {
				return off
			}
		}
	}
	return len(b)
}

// parseExtElements decodes the trailing extension elements of a SAE message.
func parseExtElements(b []byte) []ExtElement {
	var out []ExtElement
	for len(b) >= 2 {
		if b[0] != 0xff {
			return out
		}
		ln := int(b[1])
		if len(b) < 2+ln {
			return out
		}
		if ln < 1 {
			return out
		}
		out = append(out, ExtElement{ID: b[2], Data: append([]byte(nil), b[3:2+ln]...)})
		b = b[2+ln:]
	}
	return out
}
