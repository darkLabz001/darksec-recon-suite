package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
)

// Run applies every check family to a session and sorts the findings.
func Run(s *Session) {
	checkDowngrade(s)
	checkDragonfly(s)
	checkSAEPK(s)
	checkEAP(s)
	checkMgmt(s)
	checkLAN(s)
	s.SortFindings()
}

// checkDowngrade covers the transition mode, evil twin and WPA2 handshake
// vectors.
func checkDowngrade(s *Session) {
	bySSID := map[string][]*AP{}
	for _, ap := range s.APList() {
		sec := ap.Security
		if sec.Open {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-001",
				Title:    "The network is open",
				Severity: SeverityCritical,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail: "The access point does not carry an RSN information element, so every " +
					"frame is sent in the clear and any station can join.",
				Evidence: fmt.Sprintf("SSID %q on channel %d", ap.SSID, ap.Channel),
				Remedy:   "Turn on WPA3 or at least WPA2 with a strong password.",
				At:       ap.FirstSeen,
			})
		}
		if sec.WEP {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-002",
				Title:    "The network uses WEP or TKIP",
				Severity: SeverityHigh,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail:   "The pairwise ciphers include a cipher that is broken or degraded.",
				Evidence: strings.Join(sec.Ciphers, ", "),
				Remedy:   "Use CCMP with WPA3 or WPA2.",
				At:       ap.FirstSeen,
			})
		}
		if sec.WPA1 {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-003",
				Title:    "The network offers WPA1",
				Severity: SeverityHigh,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail:   "The legacy WPA vendor specific element is present, which allows an attacker to record a TKIP handshake.",
				Evidence: "a WPA vendor specific information element was seen in the beacons",
				Remedy:   "Remove WPA1 from the access point and keep WPA2 or WPA3 only.",
				At:       ap.FirstSeen,
			})
		}
		if sec.WPA2 && !sec.WPA3 && sec.Personal {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-004",
				Title:    "The network has no downgrade protection",
				Severity: SeverityMedium,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail: "The access point only offers the password based WPA2 method.  A station that " +
					"is made to believe the network is WPA2 will hand over the password verifier.",
				Evidence: "authentication and key management suites: " + strings.Join(sec.AKMs, ", "),
				Remedy:   "Move the access point to WPA3 so that the SAE handshake replaces the WPA2 one.",
				At:       ap.FirstSeen,
			})
		}
		if sec.Transition && sec.WPA3 && sec.WPA2 {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-005",
				Title:    "The network runs in WPA3 transition mode",
				Severity: SeverityMedium,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail: "The access point accepts the WPA2 method next to SAE.  An attacker who can " +
					"forge a management frame can force a station back to the older method.",
				Evidence: "authentication and key management suites: " + strings.Join(sec.AKMs, ", "),
				Remedy:   "Turn off transition mode once every station supports WPA3.",
				At:       ap.FirstSeen,
			})
		}
		if ap.OWETransitionMode {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-006",
				Title:    "The network runs in OWE transition mode",
				Severity: SeverityMedium,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail:   "The access point advertises OWE transition mode, which keeps the older method available.",
				Evidence: "a Wi-Fi Alliance OWE transition mode vendor element was seen",
				Remedy:   "Turn off OWE transition mode.",
				At:       ap.FirstSeen,
			})
		}
		if !sec.Open && !sec.MFPR {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-007",
				Title:    "Management frame protection is not required",
				Severity: SeverityHigh,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail: "The access point does not require protected management frames, so an " +
					"attacker can inject deauthentication and beacon frames and build an evil twin.",
				Evidence: "the RSN capabilities do not carry the management frame protection required bit",
				Remedy:   "Require management frame protection on the access point.",
				At:       ap.FirstSeen,
			})
		}
		if sec.WPA3 && !ap.SAEPasswordsExclusively {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-008",
				Title:    "The network does not exclude the older password methods",
				Severity: SeverityMedium,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail: "The extended capabilities do not say that the password based methods are used " +
					"exclusively, so the network can still fall back to them.",
				Evidence: "the SAE password used exclusively bit is not set",
				Remedy:   "Enable the option that uses the SAE password exclusively.",
				At:       ap.FirstSeen,
			})
		}
		if ap.Hidden {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-009",
				Title:    "The network hides its name",
				Severity: SeverityLow,
				Family:   FamilyDowngrade,
				Target:   ap.BSSID,
				Detail:   "A hidden name is no protection; it only makes the network harder to find.",
				Evidence: "the name element is present but empty",
				Remedy:   "Use a long random name instead.",
				At:       ap.FirstSeen,
			})
		}
		bySSID[ap.SSID] = append(bySSID[ap.SSID], ap)
	}

	// Evil twins: several access points answering to the same name.
	for ssid, aps := range bySSID {
		if ssid == "" || len(aps) < 2 {
			continue
		}
		for i := 0; i < len(aps); i++ {
			for j := i + 1; j < len(aps); j++ {
				a, b := aps[i], aps[j]
				if a.Security.Open != b.Security.Open {
					s.AddFinding(Finding{
						ID:       "WYM-DWN-011",
						Title:    "An evil twin serves the same name with different security",
						Severity: SeverityCritical,
						Family:   FamilyDowngrade,
						Target:   a.BSSID,
						Detail: "Two access points answer to the same name but do not offer the same " +
							"security.  The weaker one can be used to capture the handshake of a " +
							"station that believes it is joining the stronger one.",
						Evidence: fmt.Sprintf("%s offers %s while %s offers %s",
							a.BSSID, DescribeSecurity(a.Security), b.BSSID, DescribeSecurity(b.Security)),
						Remedy: "Compare the two access points and report the one that does not belong.",
						At:     a.FirstSeen,
					})
					continue
				}
				s.AddFinding(Finding{
					ID:       "WYM-DWN-010",
					Title:    "Several access points serve the same name",
					Severity: SeverityHigh,
					Family:   FamilyDowngrade,
					Target:   a.BSSID,
					Detail: "More than one access point answers to the same name.  This is normal in " +
						"large buildings, but it is also the shape an evil twin takes.",
					Evidence: fmt.Sprintf("%s and %s both serve %q", a.BSSID, b.BSSID, ssid),
					Remedy:   "Check whether every access point with this name belongs to the network operator.",
					At:       a.FirstSeen,
				})
			}
		}
	}

	// The WPA2 handshake.
	for _, h := range s.Handshakes {
		s.AddFinding(Finding{
			ID:       "WYM-DWN-012",
			Title:    "A WPA2 four way handshake was captured",
			Severity: SeverityInfo,
			Family:   FamilyDowngrade,
			Target:   h.BSSID,
			Detail: "The handshake exposes the password verifier of the network to an offline " +
				"dictionary attack.  This is the normal behaviour of WPA2 and the reason WPA3 exists.",
			Evidence: fmt.Sprintf("message %d of the handshake with station %s", h.Messages, h.Client),
			Remedy:   "Use WPA3 so that the handshake cannot be recorded and attacked offline.",
			At:       h.At,
		})
		if len(h.PMKID) > 0 {
			s.AddFinding(Finding{
				ID:       "WYM-DWN-013",
				Title:    "A PMKID was captured",
				Severity: SeverityHigh,
				Family:   FamilyDowngrade,
				Target:   h.BSSID,
				Target2:  h.Client,
				Detail: "A pairwise master key identifier was sent in the clear.  It allows an " +
					"offline dictionary attack on the network password without the full handshake.",
				Evidence: "the identifier was carried in the key data of the handshake",
				Remedy:   "Use WPA3, and disable the opportunistic roaming the identifier comes from.",
				At:       h.At,
			})
		}
	}
}

// checkDragonfly covers the SAE group strength and side channel vectors.
func checkDragonfly(s *Session) {
	for _, ex := range s.SAE {
		switch {
		case ex.Group == nil:
			s.AddFinding(Finding{
				ID:       "WYM-DFL-002",
				Title:    "The SAE handshake used an unknown finite cyclic group",
				Severity: SeverityHigh,
				Family:   FamilyDragonfly,
				Target:   ex.BSSID,
				Detail:   "The group identifier in the commit message is not one the auditor recognises.",
				Evidence: fmt.Sprintf("group %d", ex.GroupID),
				Remedy:   "Check which group the access point accepts and update the auditor if it is new.",
				At:       ex.At,
			})
		default:
			assessment := dh.AssessGroup(ex.Group)
			if !assessment.Suitable {
				s.AddFinding(Finding{
					ID:       "WYM-DFL-001",
					Title:    "The SAE handshake used a weak finite cyclic group",
					Severity: SeverityHigh,
					Family:   FamilyDragonfly,
					Target:   ex.BSSID,
					Detail: fmt.Sprintf("The group %s is too small for production use.  A weaker "+
						"group makes the password easier to recover from a recorded handshake.",
						assessment.Group.Name),
					Evidence: assessment.Detail,
					Remedy:   "Limit the access point to the groups that the reference implementation accepts.",
					At:       ex.At,
				})
			}
		}
		if ex.Validation != nil && !ex.Validation.Valid {
			detail := "The commit message failed the checks that the reference implementation performs, " +
				"which points at an implementation that does not validate the values it receives."
			if len(ex.Validation.FailedChecks()) > 0 {
				detail += " " + ex.Validation.FailedChecks()[0].Detail + "."
			}
			s.AddFinding(Finding{
				ID:       "WYM-DFL-003",
				Title:    "The SAE commit failed validation",
				Severity: SeverityCritical,
				Family:   FamilyDragonfly,
				Target:   ex.BSSID,
				Detail:   detail,
				Evidence: ex.Validation.Summary,
				Remedy: "Do not use this access point; an implementation that accepts an invalid " +
					"commit exposes the password to a side channel attack.",
				At: ex.At,
			})
		}
		if ex.Commits <= 1 && ex.Confirms == 0 {
			s.AddFinding(Finding{
				ID:       "WYM-DFL-004",
				Title:    "The SAE handshake used a single commit",
				Severity: SeverityMedium,
				Family:   FamilyDragonfly,
				Target:   ex.BSSID,
				Detail: "A single commit is not enough to mount the timing side channel, but it also " +
					"means the capture is too short to judge the behaviour of the access point.",
				Evidence: fmt.Sprintf("%d commit and %d confirm messages were seen", ex.Commits, ex.Confirms),
				Remedy:   "Record a longer handshake before drawing a conclusion.",
				At:       ex.At,
			})
		}
	}
}

// The SAE-PK method replaces the password with a key.  The network is then
// only as strong as that key, and a key that was picked by a human is as
// easy to recover with a precomputed table as a short password is.
func checkSAEPK(s *Session) {
	for _, ap := range s.APList() {
		if !ap.Security.SAEPK {
			continue
		}
		evidence := "the SAE-PK passwords used exclusively bit is set"
		if ap.SAEPK {
			evidence = "the RSN extension element signals SAE-PK"
		}
		s.AddFinding(Finding{
			ID:       "WYM-DFL-005",
			Title:    "The network authenticates with SAE-PK",
			Severity: SeverityInfo,
			Family:   FamilyDragonfly,
			Target:   ap.BSSID,
			Detail: "SAE-PK replaces the password with a key, so the strength of the network is " +
				"the strength of that key.  A key that was picked by a human is as easy to recover " +
				"with a precomputed table as a short password is.",
			Evidence: evidence,
			Remedy:   "Use a long key, keep it away from the stations and rotate it.",
			At:       ap.FirstSeen,
		})
	}
}

// checkEAP covers the EAP-pwd vectors.
func checkEAP(s *Session) {
	for _, ex := range s.EAPPwd {
		if ex.Group == nil {
			s.AddFinding(Finding{
				ID:       "WYM-EAP-004",
				Title:    "EAP-pwd used an unknown finite cyclic group",
				Severity: SeverityHigh,
				Family:   FamilyEAP,
				Target:   ex.Server,
				Detail:   "The group identifier in the EAP-pwd message is not one the auditor recognises.",
				Evidence: fmt.Sprintf("group %d", ex.GroupID),
				Remedy:   "Check which group the authentication server accepts.",
				At:       ex.At,
			})
		} else {
			assessment := dh.AssessGroup(ex.Group)
			if !assessment.Suitable {
				s.AddFinding(Finding{
					ID:       "WYM-EAP-003",
					Title:    "EAP-pwd used a weak finite cyclic group",
					Severity: SeverityHigh,
					Family:   FamilyEAP,
					Target:   ex.Server,
					Detail: fmt.Sprintf("The group %s is too small for production use.",
						assessment.Group.Name),
					Evidence: assessment.Detail,
					Remedy:   "Use one of the groups the reference implementation accepts.",
					At:       ex.At,
				})
			}
			if len(ex.RequestElem) > 0 {
				v := dh.ValidateElement(ex.Group, ex.RequestElem)
				if !v.Valid {
					s.AddFinding(Finding{
						ID:       "WYM-EAP-002",
						Title:    "The EAP-pwd server sent an invalid group element",
						Severity: SeverityCritical,
						Family:   FamilyEAP,
						Target:   ex.Server,
						Detail: "The element the server sent is not a valid member of the group it " +
							"advertised.  A server that accepts such an element is open to the " +
							"invalid curve attack.",
						Evidence: v.Summary,
						Remedy:   "Report the server to its vendor and use a different method in the meantime.",
						At:       ex.At,
					})
				}
			}
		}
		if ex.Reflect {
			s.AddFinding(Finding{
				ID:       "WYM-EAP-001",
				Title:    "The EAP-pwd exchange looks like a reflection",
				Severity: SeverityCritical,
				Family:   FamilyEAP,
				Target:   ex.Server,
				Detail: "The station answered with exactly the password value the server sent.  A " +
					"server that accepts its own value back is open to the reflection attack and " +
					"can be fooled into accepting any password.",
				Evidence: "the password value in the request and in the response are identical",
				Remedy:   "Report the server to its vendor and use another method in the meantime.",
				At:       ex.At,
			})
		}
	}
	if len(s.EAPPwd) > 0 {
		s.AddFinding(Finding{
			ID:       "WYM-EAP-005",
			Title:    "The network authenticates with EAP-pwd",
			Severity: SeverityLow,
			Family:   FamilyEAP,
			Target:   s.EAPPwd[0].Server,
			Detail: "EAP-pwd sends the password through the same channel as the data, so an " +
				"attacker in the middle can mount an offline dictionary attack on it.",
			Evidence: fmt.Sprintf("%d EAP-pwd exchanges were seen", len(s.EAPPwd)),
			Remedy:   "Use a certificate based method such as EAP-TLS.",
			At:       s.EAPPwd[0].At,
		})
	}
}

// checkMgmt covers the management frame flooding and channel switch vectors.
func checkMgmt(s *Session) {
	if s.Stats.Deauths+s.Stats.Disassocs > 0 {
		s.AddFinding(Finding{
			ID:       "WYM-MGT-003",
			Title:    "Management frame disassociations were seen",
			Severity: SeverityInfo,
			Family:   FamilyMgmt,
			Detail: fmt.Sprintf("%d deauthentication and %d disassociation frames were captured.  "+
				"A single one is normal traffic, a burst is a flood.",
				s.Stats.Deauths, s.Stats.Disassocs),
			Evidence: "the frames were counted over the whole capture",
			Remedy:   "Nothing to do unless the count is high.",
			At:       s.Started,
		})
	}
	if s.Stats.CSAs > 0 {
		s.AddFinding(Finding{
			ID:       "WYM-MGT-002",
			Title:    "Channel switch announcements were seen",
			Severity: SeverityMedium,
			Family:   FamilyMgmt,
			Target:   "",
			Detail: "A channel switch announcement makes every station in the network move to " +
				"another channel.  An unauthenticated announcement can be used to take a network " +
				"off the air for as long as the attacker keeps sending them.",
			Evidence: fmt.Sprintf("%d channel switch announcements were captured", s.Stats.CSAs),
			Remedy: "Require management frame protection so that only the access point can " +
				"announce a channel switch.",
			At: s.Started,
		})
	}
	for _, ap := range s.APList() {
		if ap.Security.Open {
			continue
		}
		if !ap.Security.MFPR {
			s.AddFinding(Finding{
				ID:       "WYM-MGT-004",
				Title:    "The access point accepts forged management frames",
				Severity: SeverityHigh,
				Family:   FamilyMgmt,
				Target:   ap.BSSID,
				Detail: "Without management frame protection an attacker can send deauthentication " +
					"frames to the stations of this network and take them off the air.",
				Evidence: "the management frame protection required bit is not set",
				Remedy:   "Require management frame protection on the access point.",
				At:       ap.FirstSeen,
			})
		}
	}
}

// checkLAN covers the ARP poisoning, rogue DHCP and group key vectors.
func checkLAN(s *Session) {
	if len(s.DHCPServer) > 1 {
		servers := make([]string, 0, len(s.DHCPServer))
		for k := range s.DHCPServer {
			servers = append(servers, k)
		}
		sort.Strings(servers)
		s.AddFinding(Finding{
			ID:       "WYM-LAN-002",
			Title:    "More than one DHCP server answered",
			Severity: SeverityHigh,
			Family:   FamilyLAN,
			Detail: "More than one server handed out addresses on this network.  A rogue server " +
				"can point the clients at a gateway it controls.",
			Evidence: strings.Join(servers, ", "),
			Remedy:   "Find the server that does not belong and remove it from the network.",
			At:       s.Started,
		})
	}
	// The group key is shared by every station of an access point, so a
	// client can inject traffic that is addressed to the whole network.
	for _, ap := range s.APList() {
		if !ap.Security.WPA3 && !ap.Security.OWE {
			continue
		}
		s.AddFinding(Finding{
			ID:       "WYM-LAN-003",
			Title:    "The group key is shared by every station of the network",
			Severity: SeverityMedium,
			Family:   FamilyLAN,
			Target:   ap.BSSID,
			Detail: "The group key is the same for every station that joins the network, so any " +
				"one of them can inject frames that the whole network accepts as genuine.",
			Evidence: "the access point uses " + DescribeSecurity(ap.Security),
			Remedy:   "Keep the group key rotation short and watch for unexpected traffic on the network.",
			At:       ap.FirstSeen,
		})
	}
	for _, ap := range s.APList() {
		if !ap.Security.Open {
			continue
		}
		s.AddFinding(Finding{
			ID:       "WYM-LAN-004",
			Title:    "The open network lets any station impersonate a client",
			Severity: SeverityMedium,
			Family:   FamilyLAN,
			Target:   ap.BSSID,
			Detail: "Without encryption there is nothing that keeps a station from using the " +
				"address of another one, which makes address poisoning possible.",
			Evidence: "the access point has no RSN information element",
			Remedy:   "Turn on WPA3 or WPA2 with a strong password.",
			At:       ap.FirstSeen,
		})
	}
}

// APVendorPrefix returns the organisation identifier of an access point.
func APVendorPrefix(ap *AP) string { return vendorPrefix(ap.BSSID) }
