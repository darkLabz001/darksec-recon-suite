package sae

import (
	"fmt"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
)

// Severity levels for a failed check.
const (
	SeverityOK       = dh.SeverityOK
	SeverityWarning  = dh.SeverityWarning
	SeverityCritical = dh.SeverityCritical
)

// Check is the outcome of a single validation step.
type Check = dh.Check

// Validation is the outcome of checking a SAE commit message against the
// parameters of the group it used.
type Validation = dh.Validation

// ValidateCommit checks a commit scalar and commit element against the
// parameters of the finite cyclic group that was used.
//
// The checks mirror the ones the reference implementation performs in
// sae_parse_commit_scalar and sae_parse_commit_element: the scalar has to
// lie in [2, p-2], the element has to lie in [2, p-2], and for a finite field
// group the element has to be a member of the prime order subgroup.  For an
// elliptic curve group the element has to be a point on the curve.
func ValidateCommit(g *Group, scalar, element []byte) *Validation {
	v := &dh.Validation{Group: g}
	if g == nil {
		v.Add("group recognised", false, SeverityCritical,
			"the finite cyclic group is not one the auditor recognises")
		v.Finish("unrecognised finite cyclic group")
		return v
	}
	sv := dh.ValidateScalar(g, scalar)
	for _, c := range sv.Checks {
		v.Add(c.Name, c.Passed, c.Severity, c.Detail)
	}
	ev := dh.ValidateElement(g, element)
	for _, c := range ev.Checks {
		v.Add(c.Name, c.Passed, c.Severity, c.Detail)
	}
	if v.Failed == 0 {
		v.Finish(fmt.Sprintf("%s commit passes every check", g.Name))
	} else {
		v.Finish(fmt.Sprintf("%s commit fails %d of %d checks",
			g.Name, v.Failed, len(v.Checks)))
	}
	return v
}

// ValidateScalar checks a scalar on its own, which is what a confirm message
// allows.
func ValidateScalar(g *Group, scalar []byte) *Validation {
	return dh.ValidateScalar(g, scalar)
}

// GroupAssessment describes how a group compares to the set that the
// reference implementation accepts for production use.
type GroupAssessment = dh.GroupAssessment

// AssessGroup rates a finite cyclic group.
func AssessGroup(g *Group) GroupAssessment { return dh.AssessGroup(g) }
