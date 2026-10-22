package dh

import (
	"fmt"
	"math/big"
)

// Severity levels for a failed check.
const (
	SeverityOK       = "ok"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Check is the outcome of a single validation step.
type Check struct {
	Name     string
	Passed   bool
	Severity string
	Detail   string
}

// Validation is the outcome of checking a group element against the
// parameters of the group it claims to belong to.
type Validation struct {
	Group   *Group
	Checks  []Check
	Valid   bool
	Failed  int
	Summary string
}

var (
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)
)

// Add appends a check to the validation.
func (v *Validation) Add(name string, ok bool, severity, detail string) {
	v.Checks = append(v.Checks, Check{
		Name:     name,
		Passed:   ok,
		Severity: severity,
		Detail:   detail,
	})
	if !ok {
		v.Failed++
	}
}

// FailedChecks returns the checks that did not pass.
func (v *Validation) FailedChecks() []Check {
	var out []Check
	for _, c := range v.Checks {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

// WorstSeverity returns the highest severity among the failed checks.
func (v *Validation) WorstSeverity() string {
	worst := SeverityOK
	for _, c := range v.FailedChecks() {
		if c.Severity == SeverityCritical {
			return SeverityCritical
		}
		worst = c.Severity
	}
	return worst
}

// Finish records the outcome of the validation.
func (v *Validation) Finish(summary string) {
	v.Valid = v.Failed == 0
	v.Summary = summary
}

// ValidateElement checks a group element against the parameters of the group.
//
// For a finite field group the element has to lie in [2, p-2] and satisfy
// element^((p-1)/2) == 1 (mod p), which is what puts it in the prime order
// subgroup.  For an elliptic curve group the element is the raw big endian
// concatenation of the x and y coordinates, both of which have to be smaller
// than the field prime, and the point has to lie on the curve.
func ValidateElement(g *Group, element []byte) *Validation {
	v := &Validation{Group: g}
	if g == nil {
		v.Add("group recognised", false, SeverityCritical,
			"the finite cyclic group is not one the auditor recognises")
		v.Finish("unrecognised finite cyclic group")
		return v
	}
	switch g.Kind {
	case KindECC:
		v.validateECCElement(element)
	default:
		v.validateFFCElement(element)
	}
	if v.Valid {
		v.Finish(fmt.Sprintf("%s element passes every check", g.Name))
	} else {
		v.Finish(fmt.Sprintf("%s element fails %d of %d checks",
			g.Name, v.Failed, len(v.Checks)))
	}
	return v
}

// ValidateScalar checks a scalar on its own.
func ValidateScalar(g *Group, scalar []byte) *Validation {
	v := &Validation{Group: g}
	if g == nil {
		v.Add("group recognised", false, SeverityCritical,
			"the finite cyclic group is not one the auditor recognises")
		v.Finish("unrecognised finite cyclic group")
		return v
	}
	p := g.Prime
	if g.Kind == KindECC {
		p = g.ECC.P
	}
	if len(scalar) != g.FieldLen {
		v.Add("scalar length", false, SeverityCritical, fmt.Sprintf(
			"scalar is %d octets, %s expects %d", len(scalar), g.Name, g.FieldLen))
	} else {
		s := new(big.Int).SetBytes(scalar)
		upper := new(big.Int).Sub(p, bigOne)
		if s.Cmp(bigOne) <= 0 || s.Cmp(upper) >= 0 {
			v.Add("scalar range", false, SeverityCritical, fmt.Sprintf(
				"scalar is outside [2, p-2] for %s", g.Name))
		} else {
			v.Add("scalar range", true, SeverityOK, fmt.Sprintf(
				"scalar lies in [2, p-2] for %s", g.Name))
		}
	}
	if v.Failed == 0 {
		v.Finish(fmt.Sprintf("%s scalar passes every check", g.Name))
	} else {
		v.Finish(fmt.Sprintf("%s scalar fails %d check(s)", g.Name, v.Failed))
	}
	return v
}

func (v *Validation) validateFFCElement(element []byte) {
	g := v.Group
	p := g.Prime
	if len(element) != g.FieldLen {
		v.Add("element length", false, SeverityCritical, fmt.Sprintf(
			"element is %d octets, %s expects %d", len(element), g.Name, g.FieldLen))
		return
	}
	e := new(big.Int).SetBytes(element)
	upper := new(big.Int).Sub(p, bigOne)
	if e.Cmp(bigOne) <= 0 || e.Cmp(upper) >= 0 {
		v.Add("element range", false, SeverityCritical, fmt.Sprintf(
			"element is outside [2, p-2] for %s", g.Name))
	} else {
		v.Add("element range", true, SeverityOK, fmt.Sprintf(
			"element lies in [2, p-2] for %s", g.Name))
	}

	q := new(big.Int).Sub(p, bigOne)
	q.Rsh(q, 1)
	r := new(big.Int).Exp(e, q, p)
	if r.Cmp(bigOne) == 0 {
		v.Add("element in prime order subgroup", true, SeverityOK, fmt.Sprintf(
			"element satisfies element^((p-1)/2) == 1 (mod p) for %s", g.Name))
	} else {
		v.Add("element in prime order subgroup", false, SeverityCritical, fmt.Sprintf(
			"element is not in the prime order subgroup for %s", g.Name))
	}
}

func (v *Validation) validateECCElement(element []byte) {
	g := v.Group
	params := g.ECC
	if len(element) != 2*g.FieldLen {
		v.Add("element length", false, SeverityCritical, fmt.Sprintf(
			"element is %d octets, %s expects %d",
			len(element), g.Name, 2*g.FieldLen))
		return
	}
	x := new(big.Int).SetBytes(element[:g.FieldLen])
	y := new(big.Int).SetBytes(element[g.FieldLen:])
	if x.Cmp(params.P) >= 0 || y.Cmp(params.P) >= 0 {
		v.Add("element coordinates in field", false, SeverityCritical, fmt.Sprintf(
			"element coordinates are not smaller than the field prime for %s", g.Name))
		return
	}
	v.Add("element coordinates in field", true, SeverityOK, fmt.Sprintf(
		"element coordinates are both smaller than the field prime for %s", g.Name))

	if OnCurve(params, x, y) {
		v.Add("element on curve", true, SeverityOK, fmt.Sprintf(
			"element is a valid point on %s", g.Name))
	} else {
		v.Add("element on curve", false, SeverityCritical, fmt.Sprintf(
			"element is not a point on %s", g.Name))
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		v.Add("element not the identity", false, SeverityCritical, fmt.Sprintf(
			"element is the point at infinity on %s", g.Name))
	} else {
		v.Add("element not the identity", true, SeverityOK, fmt.Sprintf(
			"element is not the point at infinity on %s", g.Name))
	}
}

// OnCurve reports whether (x, y) satisfies y^2 = x^3 + ax + b (mod p).
func OnCurve(p *ECCParams, x, y *big.Int) bool {
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p.P)

	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, p.P)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, new(big.Int).Mul(p.A, x))
	rhs.Add(rhs, p.B)
	rhs.Mod(rhs, p.P)

	return lhs.Cmp(rhs) == 0
}

// GroupAssessment describes how a group compares to the set that the
// reference implementation accepts for production use.
type GroupAssessment struct {
	Group    *Group
	Suitable bool
	Rating   string
	Detail   string
}

// AssessGroup rates a finite cyclic group.
func AssessGroup(g *Group) GroupAssessment {
	if g == nil {
		return GroupAssessment{Rating: RatingUnsuitable, Detail: "unrecognised group"}
	}
	detail := g.Note
	if detail == "" {
		if g.Suitable {
			detail = "accepted for production use by the reference implementation"
		} else {
			detail = "rejected for production use by the reference implementation"
		}
	}
	return GroupAssessment{
		Group:    g,
		Suitable: g.Suitable,
		Rating:   g.Rating,
		Detail:   detail,
	}
}

// PrimeIsPrime runs a Miller-Rabin test on a group prime.
func PrimeIsPrime(p *big.Int) bool {
	return p.ProbablyPrime(24)
}

// SafePrime reports whether (p-1)/2 is also prime.
func SafePrime(p *big.Int) bool {
	if !p.ProbablyPrime(24) {
		return false
	}
	q := new(big.Int).Sub(p, bigOne)
	q.Rsh(q, 1)
	return q.ProbablyPrime(24)
}

// GeneratorIsValid reports whether 2 generates the prime order subgroup of
// the safe prime p.  It holds when p is congruent to 7 modulo 8, because 2 is
// then a quadratic residue modulo p.
func GeneratorIsValid(p *big.Int) bool {
	q := new(big.Int).Sub(p, bigOne)
	q.Rsh(q, 1)
	r := new(big.Int).Exp(bigTwo, q, p)
	return r.Cmp(bigOne) == 0
}
