package sae

import (
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
)

// AuthAlgorithmSAE is the 802.11 authentication algorithm number that selects
// Simultaneous Authentication of Equals.
const AuthAlgorithmSAE uint16 = 3

// Authentication transaction sequence numbers.
const (
	SeqCommit  uint16 = 1
	SeqConfirm uint16 = 2
)

// Status codes that matter to the auditor.  The names follow hostapd's
// ieee802_11_defs.h.
const (
	StatusSuccess                     uint16 = 0
	StatusUnspecifiedFailure          uint16 = 1
	StatusAntiCloggingTokenRequired   uint16 = 76
	StatusFiniteCyclicGroupNotSupport uint16 = 77
	StatusSAEHashToElement            uint16 = 126
	StatusSAEPK                       uint16 = 127
)

// The finite cyclic groups that SAE draws from are the ones in the shared
// registry, so the SAE package re-exports them.
type (
	// Group describes one finite cyclic group.
	Group = dh.Group
	// Kind distinguishes the two families of finite cyclic group.
	Kind = dh.Kind
	// ECCParams holds the parameters of a short Weierstrass curve.
	ECCParams = dh.ECCParams
)

// Group kinds.
const (
	KindFFC = dh.KindFFC
	KindECC = dh.KindECC
)

// GroupByID returns the group with the given SAE group identifier.
func GroupByID(id uint16) (*Group, bool) { return dh.GroupByID(id) }

// Groups returns every recognised group.
func Groups() []*Group { return dh.Groups() }

// KnownGroupIDs returns the identifiers of every recognised group.
func KnownGroupIDs() []uint16 { return dh.KnownGroupIDs() }

// Describe renders a group for a report.
func Describe(id uint16) string { return dh.Describe(id) }
