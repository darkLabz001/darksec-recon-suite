// Package audit turns captured wireless traffic into a security assessment.
//
// The model keeps one record per access point, one per client station and a
// list of findings.  A finding belongs to one of the five check families that
// map onto the attack vectors the auditor covers:
//
//	downgrade  transition mode, evil twins and the WPA2 handshake
//	dragonfly  SAE group strength and side channels
//	eap        the EAP-pwd method and its reflection flaw
//	mgmt       management frame flooding and channel switch announcements
//	lan        ARP poisoning, rogue DHCP and group key injection
package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dot11"
)

// Severity ranks a finding.
type Severity string

// Severity levels.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank returns the numeric rank of a severity, higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Families of checks.
const (
	FamilyDowngrade = "downgrade"
	FamilyDragonfly = "dragonfly"
	FamilyEAP       = "eap"
	FamilyMgmt      = "mgmt"
	FamilyLAN       = "lan"
)

// Families lists the check families in report order.
func Families() []string {
	return []string{FamilyDowngrade, FamilyDragonfly, FamilyEAP, FamilyMgmt, FamilyLAN}
}

// Finding is one security observation.
type Finding struct {
	ID       string
	Title    string
	Severity Severity
	Family   string
	Target   string
	Target2  string
	Detail   string
	Evidence string
	Remedy   string
	At       time.Time
}

// String renders the finding as one line.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s", strings.ToUpper(string(f.Severity)), f.ID, f.Title)
}

// Security grades the posture of an access point.
type Security struct {
	Open       bool
	WEP        bool
	WPA1       bool
	WPA2       bool
	WPA3       bool
	Transition bool
	OWE        bool
	Enterprise bool
	Personal   bool
	MFPC       bool
	MFPR       bool
	SAEPK      bool

	GroupCipher string
	Ciphers     []string
	AKMs        []string

	Score int
	Grade string
}

// AP is an access point observed during the capture.
type AP struct {
	BSSID     string
	SSID      string
	Hidden    bool
	Channel   int
	Frequency int
	Signal    int
	HasSignal bool

	Beacons int
	Probes  int
	Assocs  int
	Auths   int

	FirstSeen time.Time
	LastSeen  time.Time

	RSN       *dot11.RSNInfo
	VendorRSN *dot11.RSNInfo
	ExtCaps   []byte
	Elements  []dot11.Element

	SAEPasswordsExclusively bool
	SAEPasswordIdentifiers  bool
	SAEPKExclusively        bool
	SAEPK                   bool
	OWETransitionMode       bool
	TransitionDisableKDE    bool

	Security Security
	Findings []Finding
}

// Label renders the access point for a report.
func (a *AP) Label() string {
	name := a.SSID
	if name == "" {
		name = "<hidden>"
	}
	return fmt.Sprintf("%s (%s)", name, a.BSSID)
}

// Client is a station observed during the capture.
type Client struct {
	MAC       string
	Vendor    string
	FirstSeen time.Time
	LastSeen  time.Time
	Frames    int
	Networks  map[string]bool
	Findings  []Finding
}

// SAEExchange is one observed SAE handshake.
type SAEExchange struct {
	BSSID      string
	Client     string
	GroupID    uint16
	Group      *dh.Group
	Validation *dh.Validation
	Token      bool
	Scalar     string
	Commits    int
	Confirms   int
	At         time.Time
}

// Handshake is one observed WPA2 four way handshake.
type Handshake struct {
	BSSID    string
	Client   string
	Messages int
	PMKID    []byte
	Complete bool
	At       time.Time
	Replayed bool
}

// EAPPwdExchange is one observed EAP-pwd exchange.
type EAPPwdExchange struct {
	Server       string
	Client       string
	GroupID      uint16
	Group        *dh.Group
	Request      []byte
	Response     []byte
	RequestElem  []byte
	ResponseElem []byte
	Reflect      bool
	Invalid      bool
	At           time.Time
}

// ARPMapping records which hardware address last claimed an address.
type ARPMapping struct {
	IP        string
	MAC       string
	FirstSeen time.Time
	LastSeen  time.Time
	Claims    int
}

// Stats holds the counters of the capture.
type Stats struct {
	Packets        int
	Bytes          int
	Management     int
	Data           int
	Control        int
	Beacons        int
	ProbeRequests  int
	ProbeResponses int
	Auths          int
	Assocs         int
	Deauths        int
	Disassocs      int
	Actions        int
	CSAs           int
	SAECommits     int
	SAEConfirms    int
	EAPOLFrames    int
	Handshakes     int
	ARPPackets     int
	DHCPPackets    int
	DNSPackets     int
	FirstSeen      time.Time
	LastSeen       time.Time
}

// Session is the result of an audit.
type Session struct {
	Source  string
	Started time.Time
	Ended   time.Time

	APs     map[string]*AP
	Clients map[string]*Client

	Findings   []Finding
	Handshakes []Handshake
	SAE        []SAEExchange
	EAPPwd     []EAPPwdExchange
	ARP        map[string]*ARPMapping
	DHCPServer map[string]bool

	Stats Stats
}

// NewSession returns an empty session.
func NewSession(source string) *Session {
	return &Session{
		Source:     source,
		APs:        map[string]*AP{},
		Clients:    map[string]*Client{},
		ARP:        map[string]*ARPMapping{},
		DHCPServer: map[string]bool{},
	}
}

// APList returns the access points ordered by signal strength and name.
func (s *Session) APList() []*AP {
	out := make([]*AP, 0, len(s.APs))
	for _, a := range s.APs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SSID != out[j].SSID {
			return out[i].SSID < out[j].SSID
		}
		return out[i].BSSID < out[j].BSSID
	})
	return out
}

// ClientList returns the client stations.
func (s *Session) ClientList() []*Client {
	out := make([]*Client, 0, len(s.Clients))
	for _, c := range s.Clients {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// AddFinding records a finding on the session.
func (s *Session) AddFinding(f Finding) {
	s.Findings = append(s.Findings, f)
}

// Clone returns a copy of the session that the checks can run on without
// disturbing the original.
//
// The access points and the clients are shared, because the checks only read
// them.  The list of findings and the counters are copied, so that findings
// added to the copy do not end up in the original.
func (s *Session) Clone() *Session {
	out := &Session{
		Source:     s.Source,
		Started:    s.Started,
		Ended:      s.Ended,
		APs:        s.APs,
		Clients:    s.Clients,
		ARP:        s.ARP,
		DHCPServer: s.DHCPServer,
		Stats:      s.Stats,
		Findings:   make([]Finding, len(s.Findings), len(s.Findings)+16),
		Handshakes: s.Handshakes,
		SAE:        s.SAE,
		EAPPwd:     s.EAPPwd,
	}
	copy(out.Findings, s.Findings)
	return out
}

// SortFindings orders the findings by severity and family.
func (s *Session) SortFindings() {
	sort.SliceStable(s.Findings, func(i, j int) bool {
		if s.Findings[i].Severity.Rank() != s.Findings[j].Severity.Rank() {
			return s.Findings[i].Severity.Rank() > s.Findings[j].Severity.Rank()
		}
		if s.Findings[i].Family != s.Findings[j].Family {
			return familyOrder(s.Findings[i].Family) < familyOrder(s.Findings[j].Family)
		}
		return s.Findings[i].ID < s.Findings[j].ID
	})
}

func familyOrder(f string) int {
	for i, x := range Families() {
		if x == f {
			return i
		}
	}
	return len(Families())
}

// CountBySeverity counts the findings of each severity.
func (s *Session) CountBySeverity() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range s.Findings {
		out[f.Severity]++
	}
	return out
}

// Overall returns the highest severity of the session and a grade.
func (s *Session) Overall() (Severity, string) {
	worst := SeverityInfo
	counts := s.CountBySeverity()
	switch {
	case counts[SeverityCritical] > 0:
		worst = SeverityCritical
	case counts[SeverityHigh] > 0:
		worst = SeverityHigh
	case counts[SeverityMedium] > 0:
		worst = SeverityMedium
	case counts[SeverityLow] > 0:
		worst = SeverityLow
	}
	grade := "A"
	switch worst {
	case SeverityCritical:
		grade = "F"
	case SeverityHigh:
		grade = "D"
	case SeverityMedium:
		grade = "C"
	case SeverityLow:
		grade = "B"
	}
	return worst, grade
}
