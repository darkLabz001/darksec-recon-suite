package dh

import (
	"math/big"
	"testing"
)

func TestGroupTableIsConsistent(t *testing.T) {
	seen := map[uint16]bool{}
	for _, g := range Groups() {
		if seen[g.ID] {
			t.Errorf("group %d appears twice in the table", g.ID)
		}
		seen[g.ID] = true

		if g.Name == "" {
			t.Errorf("group %d has no name", g.ID)
		}
		if g.FieldLen <= 0 {
			t.Errorf("group %d has no field length", g.ID)
		}
		if g.Kind != KindFFC && g.Kind != KindECC {
			t.Errorf("group %d has the unknown kind %q", g.ID, g.Kind)
		}
		switch g.Kind {
		case KindFFC:
			if g.Prime == nil {
				t.Errorf("group %d has no prime", g.ID)
				continue
			}
			if g.Prime.BitLen() != g.Bits() {
				t.Errorf("group %d has a %d bit prime but claims %d bits",
					g.ID, g.Prime.BitLen(), g.Bits())
			}
		case KindECC:
			if g.ECC == nil {
				t.Errorf("group %d has no curve parameters", g.ID)
				continue
			}
			// An elliptic curve field is rounded up to a whole number of
			// octets, so P-521 is carried in 66 octets.
			if bits := g.ECC.P.BitLen(); bits < g.Bits()-8 || bits > g.Bits() {
				t.Errorf("group %d has a %d bit field prime but claims %d bits",
					g.ID, bits, g.Bits())
			}
		}
	}
}

func TestGroupByID(t *testing.T) {
	for _, id := range KnownGroupIDs() {
		g, ok := GroupByID(id)
		if !ok {
			t.Fatalf("group %d is listed but cannot be looked up", id)
		}
		if g.ID != id {
			t.Errorf("group %d was looked up as group %d", id, g.ID)
		}
	}
	if _, ok := GroupByID(22); ok {
		t.Error("group 22 must not be in the table, hostapd and Wireshark disagree about it")
	}
	if _, ok := GroupByID(9999); ok {
		t.Error("an unknown group was found")
	}
}

func TestFFCPrimesAreSafePrimes(t *testing.T) {
	// The safe prime property is what makes the finite cyclic groups
	// usable, so it is checked rather than assumed.
	for _, g := range Groups() {
		if g.Kind != KindFFC {
			continue
		}
		// A Miller-Rabin test with many rounds on an 8192 bit prime takes
		// seconds, so the large groups are given fewer rounds.
		rounds := 24
		if g.Bits() > 3072 {
			rounds = 4
		}
		if !g.Prime.ProbablyPrime(rounds) {
			t.Errorf("the prime of %s is not prime", g.Name)
			continue
		}
		if !isSafePrime(g.Prime, rounds) {
			t.Errorf("the prime of %s is not a safe prime", g.Name)
		}
	}
}

// isSafePrime reports whether (p-1)/2 is prime as well.
func isSafePrime(p *big.Int, rounds int) bool {
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Rsh(q, 1)
	return q.ProbablyPrime(rounds)
}

func TestGeneratorIsValid(t *testing.T) {
	for _, g := range Groups() {
		if g.Kind != KindFFC {
			continue
		}
		if !GeneratorIsValid(g.Prime) {
			t.Errorf("the generator of %s is not valid", g.Name)
		}
	}
}

func TestElementAndTagLengths(t *testing.T) {
	cases := []struct {
		id      uint16
		element int
		tag     int
	}{
		{1, 96, 32},
		{2, 128, 32},
		{5, 192, 32},
		{14, 256, 32},
		{15, 384, 48},
		{16, 512, 64},
		{17, 768, 64},
		{18, 1024, 64},
		{19, 64, 32},
		{20, 96, 48},
		{21, 132, 64},
		{25, 48, 32},
		{26, 56, 32},
		{27, 56, 32},
		{28, 64, 32},
		{29, 96, 48},
		{30, 128, 64},
	}
	for _, c := range cases {
		g, ok := GroupByID(c.id)
		if !ok {
			t.Fatalf("group %d is not known", c.id)
		}
		if got := g.ElementLen(); got != c.element {
			t.Errorf("group %d has an element length of %d, want %d", c.id, got, c.element)
		}
		if got := g.TagLen(); got != c.tag {
			t.Errorf("group %d has a tag length of %d, want %d", c.id, got, c.tag)
		}
	}
}

func TestSuitabilityMatchesHostapd(t *testing.T) {
	// hostapd's dragonfly_suitable_group accepts 3072 bit and larger
	// finite field groups and the NIST curves, and rejects everything
	// else.
	suitable := map[uint16]bool{15: true, 16: true, 17: true, 18: true, 19: true, 20: true, 21: true}
	for _, g := range Groups() {
		want := suitable[g.ID]
		if g.Suitable != want {
			t.Errorf("group %d is marked suitable=%v, want %v", g.ID, g.Suitable, want)
		}
	}
}

func TestAssessGroup(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	a := AssessGroup(g)
	if !a.Suitable {
		t.Error("P-256 must be rated suitable")
	}
	if a.Rating != RatingStrong {
		t.Errorf("P-256 is rated %q, want %q", a.Rating, RatingStrong)
	}
	if a.Detail == "" {
		t.Error("the assessment carries no detail")
	}

	none := AssessGroup(nil)
	if none.Suitable {
		t.Error("an unknown group must not be suitable")
	}
}

func TestValidateElementAcceptsAValidPoint(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	// The generator is on the curve by construction.
	element := make([]byte, g.ElementLen())
	g.ECC.Gx.FillBytes(element[:g.FieldLen])
	g.ECC.Gy.FillBytes(element[g.FieldLen:])

	v := ValidateElement(g, element)
	if !v.Valid {
		t.Fatalf("the generator must pass validation: %s", v.Summary)
	}
	if len(v.FailedChecks()) != 0 {
		t.Errorf("the generator failed %d checks", len(v.FailedChecks()))
	}
}

func TestValidateElementRejectsAPointThatIsNotOnTheCurve(t *testing.T) {
	g, ok := GroupByID(19)
	if !ok {
		t.Fatal("group 19 is not known")
	}
	element := make([]byte, g.ElementLen())
	g.ECC.Gx.FillBytes(element[:g.FieldLen])
	// Change the y coordinate so that the point no longer lies on the curve.
	y := new(big.Int).Add(g.ECC.Gy, big.NewInt(1))
	y.FillBytes(element[g.FieldLen:])

	v := ValidateElement(g, element)
	if v.Valid {
		t.Fatal("a point that is not on the curve must not pass validation")
	}
	if v.WorstSeverity() != SeverityCritical {
		t.Errorf("the worst severity is %q, want %q", v.WorstSeverity(), SeverityCritical)
	}
}

func TestValidateElementRejectsAShortElement(t *testing.T) {
	g, _ := GroupByID(19)
	v := ValidateElement(g, []byte{1, 2, 3})
	if v.Valid {
		t.Fatal("a short element must not pass validation")
	}
}

func TestValidateElementAcceptsAValidFFCElement(t *testing.T) {
	g, ok := GroupByID(15)
	if !ok {
		t.Fatal("group 15 is not known")
	}
	// The generator of a finite field group is 2, which is in the prime
	// order subgroup of a safe prime.
	element := make([]byte, g.FieldLen)
	element[g.FieldLen-1] = 2

	v := ValidateElement(g, element)
	if !v.Valid {
		t.Fatalf("the generator must pass validation: %s", v.Summary)
	}
}

func TestValidateScalar(t *testing.T) {
	g, _ := GroupByID(19)
	scalar := make([]byte, g.FieldLen)
	scalar[g.FieldLen-1] = 5
	if v := ValidateScalar(g, scalar); !v.Valid {
		t.Errorf("a small scalar must pass validation: %s", v.Summary)
	}

	zero := make([]byte, g.FieldLen)
	if v := ValidateScalar(g, zero); v.Valid {
		t.Error("a zero scalar must not pass validation")
	}

	short := make([]byte, g.FieldLen-1)
	if v := ValidateScalar(g, short); v.Valid {
		t.Error("a scalar of the wrong length must not pass validation")
	}
}

func TestDescribeUnknownGroup(t *testing.T) {
	got := Describe(9999)
	if got == "" {
		t.Fatal("the description is empty")
	}
	if Describe(19) == "" {
		t.Fatal("the description of a known group is empty")
	}
}
