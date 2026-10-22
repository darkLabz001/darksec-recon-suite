package audit

import "fmt"

// ScoreSecurity scores the posture of an access point out of a hundred.
//
// The score starts from the strongest security the access point offers and is
// then adjusted for the weaknesses that the checks report.
func ScoreSecurity(sec Security, ap *AP) int {
	score := 0
	switch {
	case sec.Open:
		score = 5
	case sec.WEP:
		score = 15
	case sec.WPA1 && !sec.WPA2 && !sec.WPA3:
		score = 25
	case sec.WPA3 && !sec.Transition:
		score = 92
	case sec.WPA3 && sec.Transition:
		score = 68
	case sec.WPA2 && !sec.Transition:
		score = 58
	case sec.WPA2:
		score = 48
	case sec.Enterprise:
		score = 72
	default:
		score = 30
	}

	if !sec.Open && !sec.MFPR {
		// Without management frame protection a station can be forced
		// off the network with unauthenticated frames.
		score -= 8
	}
	if sec.Transition {
		// A transition mode network accepts the older method as well.
		score -= 4
	}
	if ap != nil && ap.SAEPKExclusively {
		score += 4
	}
	if ap != nil && ap.SAEPasswordsExclusively {
		score += 4
	}
	if sec.WEP {
		score -= 20
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

// gradeFor maps a score to a letter grade.
func gradeFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}

// GradeDescription explains a grade.
func GradeDescription(grade string) string {
	switch grade {
	case "A":
		return "the access point resists every attack vector the auditor covers"
	case "B":
		return "the access point is sound with minor gaps"
	case "C":
		return "the access point has weaknesses an attacker can use"
	case "D":
		return "the access point is badly configured"
	case "F":
		return "the access point offers no meaningful protection"
	}
	return "not assessed"
}

// DescribeSecurity renders the security posture of an access point.
func DescribeSecurity(sec Security) string {
	switch {
	case sec.Open:
		return "open"
	case sec.WEP:
		return "WEP"
	case sec.WPA1 && !sec.WPA2 && !sec.WPA3:
		return "WPA"
	case sec.WPA3 && sec.Transition:
		return "WPA3 transition mode"
	case sec.WPA3:
		return "WPA3"
	case sec.OWE:
		return "OWE"
	case sec.WPA2 && sec.Transition:
		return "WPA2 transition mode"
	case sec.WPA2:
		return "WPA2"
	case sec.Enterprise:
		return "WPA2 enterprise"
	}
	return "unknown"
}

// SecurityLabel renders the posture with its grade.
func SecurityLabel(sec Security) string {
	return fmt.Sprintf("%s (%s, %d/100)", DescribeSecurity(sec), sec.Grade, sec.Score)
}
