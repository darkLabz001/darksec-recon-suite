package audit

import (
	"testing"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
)

// newAP returns an access point with the given posture.
func newAP(bssid, ssid string, sec Security) *AP {
	ap := &AP{
		BSSID:     bssid,
		SSID:      ssid,
		Channel:   6,
		FirstSeen: time.Unix(1700000000, 0),
	}
	sec.Score = ScoreSecurity(sec, ap)
	sec.Grade = gradeFor(sec.Score)
	ap.Security = sec
	return ap
}

// hasFinding reports whether the session carries a finding with the given id.
func hasFinding(s *Session, id string) bool {
	for _, f := range s.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// finding returns the finding with the given id.
func finding(s *Session, id string) (Finding, bool) {
	for _, f := range s.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func TestCheckDowngradeReportsAnOpenNetwork(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:01"] = newAP("aa:bb:cc:dd:ee:01", "guest", Security{Open: true})
	Run(s)

	f, ok := finding(s, "WYM-DWN-001")
	if !ok {
		t.Fatal("the open network was not reported")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityCritical)
	}
	if f.Family != FamilyDowngrade {
		t.Errorf("the family is %q, want %q", f.Family, FamilyDowngrade)
	}
	if f.Target != "aa:bb:cc:dd:ee:01" {
		t.Errorf("the target is %q", f.Target)
	}
	if f.Detail == "" || f.Remedy == "" {
		t.Error("the finding carries no detail or no remedy")
	}
}

func TestCheckDowngradeReportsTransitionMode(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:02"] = newAP("aa:bb:cc:dd:ee:02", "home", Security{
		WPA2: true, WPA3: true, Transition: true, Personal: true, MFPC: true, MFPR: true,
		AKMs: []string{"PSK", "SAE"},
	})
	Run(s)

	f, ok := finding(s, "WYM-DWN-005")
	if !ok {
		t.Fatal("the transition mode was not reported")
	}
	if f.Severity != SeverityMedium {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityMedium)
	}
}

func TestCheckDowngradeReportsAnEvilTwin(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:03"] = newAP("aa:bb:cc:dd:ee:03", "cafe", Security{
		WPA2: true, Personal: true, MFPC: true, MFPR: true, AKMs: []string{"PSK"},
	})
	s.APs["aa:bb:cc:dd:ee:04"] = newAP("aa:bb:cc:dd:ee:04", "cafe", Security{
		Open: true,
	})
	Run(s)

	if !hasFinding(s, "WYM-DWN-011") {
		t.Error("the evil twin was not reported")
	}
	if hasFinding(s, "WYM-DWN-010") {
		t.Error("a pair with a different security is reported as an evil twin only")
	}
	f, _ := finding(s, "WYM-DWN-011")
	if f.Severity != SeverityCritical {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityCritical)
	}
}

func TestCheckDowngradeReportsTwoAccessPointsWithTheSameSecurity(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:03"] = newAP("aa:bb:cc:dd:ee:03", "cafe", Security{
		WPA2: true, Personal: true, MFPC: true, MFPR: true, AKMs: []string{"PSK"},
	})
	s.APs["aa:bb:cc:dd:ee:04"] = newAP("aa:bb:cc:dd:ee:04", "cafe", Security{
		WPA2: true, Personal: true, MFPC: true, MFPR: true, AKMs: []string{"PSK"},
	})
	Run(s)

	if !hasFinding(s, "WYM-DWN-010") {
		t.Error("the duplicated name was not reported")
	}
	if hasFinding(s, "WYM-DWN-011") {
		t.Error("two access points with the same security are not an evil twin")
	}
}

func TestCheckDowngradeReportsMissingManagementFrameProtection(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:05"] = newAP("aa:bb:cc:dd:ee:05", "lab", Security{
		WPA2: true, Personal: true, MFPC: true,
	})
	Run(s)
	if !hasFinding(s, "WYM-DWN-007") {
		t.Error("the missing management frame protection was not reported")
	}
}

func TestCheckDowngradeReportsTheCapturedHandshake(t *testing.T) {
	s := NewSession("test")
	s.Handshakes = []Handshake{{
		BSSID: "aa:bb:cc:dd:ee:06", Client: "11:22:33:44:55:66",
		Messages: 4, Complete: true, At: time.Unix(1700000010, 0),
	}}
	Run(s)

	f, ok := finding(s, "WYM-DWN-012")
	if !ok {
		t.Fatal("the captured handshake was not reported")
	}
	if f.Severity != SeverityInfo {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityInfo)
	}
}

func TestCheckDowngradeReportsACapturedPMKID(t *testing.T) {
	s := NewSession("test")
	s.Handshakes = []Handshake{{
		BSSID: "aa:bb:cc:dd:ee:07", Client: "11:22:33:44:55:77",
		Messages: 2, PMKID: []byte{1, 2, 3, 4}, At: time.Unix(1700000010, 0),
	}}
	Run(s)

	f, ok := finding(s, "WYM-DWN-013")
	if !ok {
		t.Fatal("the captured PMKID was not reported")
	}
	if f.Target2 != "11:22:33:44:55:77" {
		t.Errorf("the second target is %q", f.Target2)
	}
}

func TestCheckDragonflyReportsAWeakGroup(t *testing.T) {
	weak, ok := dh.GroupByID(1)
	if !ok {
		t.Fatal("group 1 is not known")
	}
	s := NewSession("test")
	s.SAE = []SAEExchange{{
		BSSID: "aa:bb:cc:dd:ee:08", Client: "11:22:33:44:55:88",
		GroupID: weak.ID, Group: weak, Commits: 1, At: time.Unix(1700000020, 0),
	}}
	Run(s)

	f, ok := finding(s, "WYM-DFL-001")
	if !ok {
		t.Fatal("the weak group was not reported")
	}
	if f.Severity != SeverityHigh {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityHigh)
	}
}

func TestCheckDragonflyReportsAnUnknownGroup(t *testing.T) {
	s := NewSession("test")
	s.SAE = []SAEExchange{{
		BSSID: "aa:bb:cc:dd:ee:09", Client: "11:22:33:44:55:99",
		GroupID: 4242, Commits: 1, At: time.Unix(1700000020, 0),
	}}
	Run(s)
	if !hasFinding(s, "WYM-DFL-002") {
		t.Error("the unknown group was not reported")
	}
}

func TestCheckDragonflyReportsAFailedValidation(t *testing.T) {
	g, _ := dh.GroupByID(19)
	s := NewSession("test")
	s.SAE = []SAEExchange{{
		BSSID: "aa:bb:cc:dd:ee:0a", Client: "11:22:33:44:55:aa",
		GroupID: g.ID, Group: g, Commits: 1, At: time.Unix(1700000020, 0),
		Validation: &dh.Validation{
			Group: g, Valid: false, Failed: 1, Summary: "one check failed",
		},
	}}
	Run(s)

	f, ok := finding(s, "WYM-DFL-003")
	if !ok {
		t.Fatal("the failed validation was not reported")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityCritical)
	}
}

func TestCheckSAEPKReportsTheKeyBasedMethod(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:0c"] = newAP("aa:bb:cc:dd:ee:0c", "sae-pk", Security{
		WPA3: true, Personal: true, SAEPK: true,
	})
	Run(s)

	f, ok := finding(s, "WYM-DFL-005")
	if !ok {
		t.Fatal("the use of SAE-PK was not reported")
	}
	if f.Severity != SeverityInfo {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityInfo)
	}
	if f.Family != FamilyDragonfly {
		t.Errorf("the family is %q, want %q", f.Family, FamilyDragonfly)
	}
	if f.Target != "aa:bb:cc:dd:ee:0c" {
		t.Errorf("the target is %q", f.Target)
	}
	if f.Remedy == "" {
		t.Error("the finding carries no remedy")
	}
}

func TestCheckSAEPKIsQuietWithoutTheMethod(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:0d"] = newAP("aa:bb:cc:dd:ee:0d", "plain", Security{
		WPA3: true, Personal: true,
	})
	Run(s)

	if hasFinding(s, "WYM-DFL-005") {
		t.Error("a network that does not use SAE-PK must not be reported")
	}
}

func TestCheckEAPReportsAReflection(t *testing.T) {
	g, _ := dh.GroupByID(19)
	s := NewSession("test")
	s.EAPPwd = []EAPPwdExchange{{
		Server: "aa:bb:cc:dd:ee:0b", Client: "11:22:33:44:55:bb",
		GroupID: g.ID, Group: g, Reflect: true, At: time.Unix(1700000030, 0),
	}}
	Run(s)

	f, ok := finding(s, "WYM-EAP-001")
	if !ok {
		t.Fatal("the reflection was not reported")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityCritical)
	}
	if !hasFinding(s, "WYM-EAP-005") {
		t.Error("the use of EAP-pwd was not reported")
	}
}

func TestCheckEAPReportsAnInvalidElement(t *testing.T) {
	g, _ := dh.GroupByID(19)
	s := NewSession("test")
	s.EAPPwd = []EAPPwdExchange{{
		Server: "aa:bb:cc:dd:ee:0c", Client: "11:22:33:44:55:cc",
		GroupID: g.ID, Group: g, RequestElem: []byte{1, 2, 3},
		At: time.Unix(1700000030, 0),
	}}
	Run(s)
	if !hasFinding(s, "WYM-EAP-002") {
		t.Error("the invalid element was not reported")
	}
}

func TestCheckMgmtReportsAChannelSwitchAnnouncement(t *testing.T) {
	s := NewSession("test")
	s.Stats.CSAs = 12
	Run(s)

	f, ok := finding(s, "WYM-MGT-002")
	if !ok {
		t.Fatal("the channel switch announcement was not reported")
	}
	if f.Severity != SeverityMedium {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityMedium)
	}
}

func TestCheckMgmtReportsDisassociations(t *testing.T) {
	s := NewSession("test")
	s.Stats.Deauths = 4
	s.Stats.Disassocs = 2
	Run(s)
	if !hasFinding(s, "WYM-MGT-003") {
		t.Error("the disassociations were not reported")
	}
}

func TestCheckLANReportsTwoDHCPServers(t *testing.T) {
	s := NewSession("test")
	s.DHCPServer["aa:bb:cc:dd:ee:0d"] = true
	s.DHCPServer["aa:bb:cc:dd:ee:0e"] = true
	Run(s)

	f, ok := finding(s, "WYM-LAN-002")
	if !ok {
		t.Fatal("the second DHCP server was not reported")
	}
	if f.Severity != SeverityHigh {
		t.Errorf("the severity is %s, want %s", f.Severity, SeverityHigh)
	}
}

func TestCheckLANReportsTheSharedGroupKey(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:0f"] = newAP("aa:bb:cc:dd:ee:0f", "mesh", Security{
		WPA3: true, MFPC: true, MFPR: true, AKMs: []string{"SAE"},
	})
	Run(s)
	if !hasFinding(s, "WYM-LAN-003") {
		t.Error("the shared group key was not reported")
	}
}

func TestOverallGrading(t *testing.T) {
	cases := []struct {
		severity Severity
		grade    string
	}{
		{SeverityCritical, "F"},
		{SeverityHigh, "D"},
		{SeverityMedium, "C"},
		{SeverityLow, "B"},
		{SeverityInfo, "A"},
	}
	for _, c := range cases {
		s := NewSession("test")
		s.AddFinding(Finding{ID: "WYM-TEST-001", Severity: c.severity})
		sev, grade := s.Overall()
		if sev != c.severity {
			t.Errorf("the severity reads %s, want %s", sev, c.severity)
		}
		if grade != c.grade {
			t.Errorf("the grade reads %s, want %s", grade, c.grade)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	s := NewSession("test")
	s.AddFinding(Finding{ID: "A", Severity: SeverityHigh})
	s.AddFinding(Finding{ID: "B", Severity: SeverityHigh})
	s.AddFinding(Finding{ID: "C", Severity: SeverityLow})
	counts := s.CountBySeverity()
	if counts[SeverityHigh] != 2 {
		t.Errorf("the high count is %d, want 2", counts[SeverityHigh])
	}
	if counts[SeverityLow] != 1 {
		t.Errorf("the low count is %d, want 1", counts[SeverityLow])
	}
}

func TestCloneKeepsTheFindingsApart(t *testing.T) {
	s := NewSession("test")
	s.APs["aa:bb:cc:dd:ee:10"] = newAP("aa:bb:cc:dd:ee:10", "open", Security{Open: true})
	s.AddFinding(Finding{ID: "WYM-TEST-001", Severity: SeverityInfo})

	clone := s.Clone()
	Run(clone)

	if len(s.Findings) != 1 {
		t.Errorf("the original carries %d findings, want 1", len(s.Findings))
	}
	if len(clone.Findings) < 2 {
		t.Errorf("the clone carries %d findings, want at least 2", len(clone.Findings))
	}
	if clone.APs["aa:bb:cc:dd:ee:10"] == nil {
		t.Error("the clone lost the access point")
	}
}

func TestScoreSecurity(t *testing.T) {
	cases := []struct {
		name string
		sec  Security
		want int
	}{
		{"open", Security{Open: true}, 5},
		{"wep", Security{WEP: true}, 0},
		{"wpa3", Security{WPA3: true, MFPR: true}, 92},
		{"wpa3 transition", Security{WPA3: true, Transition: true, MFPR: true}, 64},
		{"wpa2", Security{WPA2: true, MFPR: true}, 58},
	}
	for _, c := range cases {
		got := ScoreSecurity(c.sec, nil)
		if got != c.want {
			t.Errorf("%s scores %d, want %d", c.name, got, c.want)
		}
	}
}

func TestDescribeSecurity(t *testing.T) {
	cases := []struct {
		sec  Security
		want string
	}{
		{Security{Open: true}, "open"},
		{Security{WEP: true}, "WEP"},
		{Security{WPA3: true, Transition: true}, "WPA3 transition mode"},
		{Security{WPA3: true}, "WPA3"},
		{Security{OWE: true}, "OWE"},
		{Security{WPA2: true}, "WPA2"},
		{Security{Enterprise: true}, "WPA2 enterprise"},
	}
	for _, c := range cases {
		if got := DescribeSecurity(c.sec); got != c.want {
			t.Errorf("the posture reads %q, want %q", got, c.want)
		}
	}
}

func TestFamiliesAreStable(t *testing.T) {
	want := []string{FamilyDowngrade, FamilyDragonfly, FamilyEAP, FamilyMgmt, FamilyLAN}
	got := Families()
	if len(got) != len(want) {
		t.Fatalf("the list holds %d families, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("the family at %d reads %q, want %q", i, got[i], want[i])
		}
	}
}
