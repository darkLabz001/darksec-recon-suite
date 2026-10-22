// Package dh holds the finite cyclic group parameters that the IEEE 802.11
// authentication methods share.
//
// The SAE (WPA3-Personal) and EAP-pwd (RFC 5216) methods draw their groups
// from the same IANA registry, and the identifiers and field sizes that appear
// on the wire are the ones implemented by hostapd (src/crypto/dh_groups.c for
// the finite field groups, src/crypto/crypto_openssl.c for the elliptic curve
// groups) and by the Wireshark dissector (get_scalar_len and
// get_group_element_len in packet-ieee80211.c).
package dh

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// Kind distinguishes the two families of finite cyclic group.
type Kind string

// Group kinds.
const (
	KindFFC Kind = "ffc"
	KindECC Kind = "ecc"
)

// Ratings describe how a group compares to the set that hostapd accepts for
// production use (dragonfly_suitable_group in src/common/dragonfly.c).
const (
	RatingStrong      = "strong"
	RatingLegacy      = "legacy"
	RatingWeak        = "weak"
	RatingUnsuitable  = "unsuitable"
	RatingNonStandard = "non-standard"
)

// ECCParams holds the parameters of a short Weierstrass curve.
type ECCParams struct {
	P, A, B, Gx, Gy, N *big.Int
}

// Group describes one finite cyclic group.
type Group struct {
	ID       uint16
	Name     string
	Kind     Kind
	FieldLen int // field size in octets
	Prime    *big.Int
	ECC      *ECCParams
	Suitable bool
	Rating   string
	Note     string
}

// ElementLen is the length of a group element in octets.
func (g *Group) ElementLen() int {
	if g.Kind == KindECC {
		return 2 * g.FieldLen
	}
	return g.FieldLen
}

// TagLen is the length of the SAE confirm tag in octets.  It follows
// sae_ecc_prime_len_2_hash_len and sae_ffc_prime_len_2_hash_len in
// hostapd's src/common/sae.c.
func (g *Group) TagLen() int {
	switch g.Kind {
	case KindECC:
		switch {
		case g.FieldLen <= 32:
			return 32
		case g.FieldLen <= 48:
			return 48
		default:
			return 64
		}
	default:
		switch {
		case g.FieldLen <= 256:
			return 32
		case g.FieldLen <= 384:
			return 48
		default:
			return 64
		}
	}
}

// Bits is the field size in bits.
func (g *Group) Bits() int { return g.FieldLen * 8 }

// PrimeLen is the length of the group prime in octets.
func (g *Group) PrimeLen() int { return g.FieldLen }

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("dh: bad constant " + s)
	}
	return n
}

func eccParams(c curve) *ECCParams {
	return &ECCParams{
		P:  mustHex(c.p),
		A:  mustHex(c.a),
		B:  mustHex(c.b),
		Gx: mustHex(c.gx),
		Gy: mustHex(c.gy),
		N:  mustHex(c.n),
	}
}

func stdECC(c elliptic.Curve) *ECCParams {
	p := c.Params()
	// The curves in the standard library all use a = -3.
	a := new(big.Int).Sub(p.P, big.NewInt(3))
	return &ECCParams{
		P:  new(big.Int).Set(p.P),
		A:  a,
		B:  new(big.Int).Set(p.B),
		Gx: new(big.Int).Set(p.Gx),
		Gy: new(big.Int).Set(p.Gy),
		N:  new(big.Int).Set(p.N),
	}
}

// FFCPrime returns the MODP prime of the given field size in octets.
func FFCPrime(fieldLen int) *big.Int {
	switch fieldLen {
	case 96:
		return mustHex(prime768)
	case 128:
		return mustHex(prime1024)
	case 192:
		return mustHex(prime1536)
	case 256:
		return mustHex(prime2048)
	case 384:
		return mustHex(prime3072)
	case 512:
		return mustHex(prime4096)
	case 768:
		return mustHex(prime6144)
	case 1024:
		return mustHex(prime8192)
	}
	return nil
}

// groups lists every group the auditor recognises.
var groups = []*Group{
	{
		ID: 1, Name: "FFC 768-bit MODP", Kind: KindFFC, FieldLen: 96,
		Prime: FFCPrime(96), Suitable: false, Rating: RatingUnsuitable,
		Note: "Below the 3072 bit floor that hostapd enforces for production use",
	},
	{
		ID: 2, Name: "FFC 1024-bit MODP", Kind: KindFFC, FieldLen: 128,
		Prime: FFCPrime(128), Suitable: false, Rating: RatingUnsuitable,
		Note: "Below the 3072 bit floor that hostapd enforces for production use",
	},
	{
		ID: 5, Name: "FFC 1536-bit MODP", Kind: KindFFC, FieldLen: 192,
		Prime: FFCPrime(192), Suitable: false, Rating: RatingUnsuitable,
		Note: "Below the 3072 bit floor that hostapd enforces for production use",
	},
	{
		ID: 14, Name: "FFC 2048-bit MODP", Kind: KindFFC, FieldLen: 256,
		Prime: FFCPrime(256), Suitable: false, Rating: RatingWeak,
		Note: "Below the 3072 bit floor that hostapd enforces for production use",
	},
	{
		ID: 15, Name: "FFC 3072-bit MODP", Kind: KindFFC, FieldLen: 384,
		Prime: FFCPrime(384), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 16, Name: "FFC 4096-bit MODP", Kind: KindFFC, FieldLen: 512,
		Prime: FFCPrime(512), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 17, Name: "FFC 6144-bit MODP", Kind: KindFFC, FieldLen: 768,
		Prime: FFCPrime(768), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 18, Name: "FFC 8192-bit MODP", Kind: KindFFC, FieldLen: 1024,
		Prime: FFCPrime(1024), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 19, Name: "ECC P-256", Kind: KindECC, FieldLen: 32,
		ECC: stdECC(elliptic.P256()), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 20, Name: "ECC P-384", Kind: KindECC, FieldLen: 48,
		ECC: stdECC(elliptic.P384()), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 21, Name: "ECC P-521", Kind: KindECC, FieldLen: 66,
		ECC: stdECC(elliptic.P521()), Suitable: true, Rating: RatingStrong,
	},
	{
		ID: 25, Name: "ECC P-192", Kind: KindECC, FieldLen: 24,
		ECC: eccParams(curveP192), Suitable: false, Rating: RatingWeak,
		Note: "Field far too small for a password authenticated key exchange",
	},
	{
		ID: 26, Name: "ECC P-224", Kind: KindECC, FieldLen: 28,
		ECC: eccParams(curveP224), Suitable: false, Rating: RatingWeak,
		Note: "Field far too small for a password authenticated key exchange",
	},
	{
		ID: 27, Name: "ECC Brainpool P-224", Kind: KindECC, FieldLen: 28,
		ECC: eccParams(curveBrainpoolP224), Suitable: false, Rating: RatingNonStandard,
		Note: "Brainpool curves leak more timing information and are not enabled by hostapd",
	},
	{
		ID: 28, Name: "ECC Brainpool P-256", Kind: KindECC, FieldLen: 32,
		ECC: eccParams(curveBrainpoolP256), Suitable: false, Rating: RatingNonStandard,
		Note: "Brainpool curves leak more timing information and are not enabled by hostapd",
	},
	{
		ID: 29, Name: "ECC Brainpool P-384", Kind: KindECC, FieldLen: 48,
		ECC: eccParams(curveBrainpoolP384), Suitable: false, Rating: RatingNonStandard,
		Note: "Brainpool curves leak more timing information and are not enabled by hostapd",
	},
	{
		ID: 30, Name: "ECC Brainpool P-512", Kind: KindECC, FieldLen: 64,
		ECC: eccParams(curveBrainpoolP512), Suitable: false, Rating: RatingNonStandard,
		Note: "Brainpool curves leak more timing information and are not enabled by hostapd",
	},
}

// GroupByID returns the group with the given identifier.
func GroupByID(id uint16) (*Group, bool) {
	for _, g := range groups {
		if g.ID == id {
			return g, true
		}
	}
	return nil, false
}

// Groups returns every recognised group.
func Groups() []*Group { return groups }

// KnownGroupIDs returns the identifiers of every recognised group.
func KnownGroupIDs() []uint16 {
	out := make([]uint16, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.ID)
	}
	return out
}

// Describe renders a group for a report.
func Describe(id uint16) string {
	g, ok := GroupByID(id)
	if !ok {
		return fmt.Sprintf("group %d (unknown)", id)
	}
	return fmt.Sprintf("group %d (%s, %d bit)", id, g.Name, g.Bits())
}
