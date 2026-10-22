package osdetect

import "sort"

// classify scores the observed fingerprint against every signature and
// returns the candidates ordered by confidence, best first.
func classify(fp Fingerprint) []Match {
	out := make([]Match, 0, len(signatures))
	for _, sig := range signatures {
		acc := 100

		if initialTTL(fp.TTL) != sig.ttl {
			acc -= 30
		}
		if fp.Window != 0 && !containsWindow(sig.windows, fp.Window) {
			acc -= 20
		}
		// The MSS follows the link MTU more than the operating system, so
		// it is only a weak signal.
		if fp.MSS != 0 && sig.mss != 0 && fp.MSS != sig.mss {
			acc -= 5
		}
		if fp.Options != "" && sig.options != fp.Options {
			acc -= 15
		}
		if fp.WindowScale >= 0 && sig.wscale >= 0 && fp.WindowScale != sig.wscale {
			acc -= 8
		}
		if fp.SACKOK != sig.sackOK {
			acc -= 4
		}
		if fp.Timestamp != sig.ts {
			acc -= 4
		}

		if acc < 0 {
			acc = 0
		}
		out = append(out, Match{
			Name:        sig.name,
			Description: sig.description,
			Accuracy:    acc,
		})
	}

	// A stable sort keeps the database order for equal scores, so a generic
	// entry such as "Linux" is preferred over a more specific one such as
	// "Android" when the two are otherwise indistinguishable.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Accuracy > out[j].Accuracy
	})
	return out
}

func containsWindow(windows []uint16, w uint16) bool {
	for _, candidate := range windows {
		if candidate == w {
			return true
		}
	}
	return false
}
