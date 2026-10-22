// Package report renders an audit session as JSON, as plain text and as a
// self contained HTML page.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/version"
)

// Document is the machine readable form of a report.
type Document struct {
	Tool         string           `json:"tool"`
	Version      version.Info     `json:"version"`
	Source       string           `json:"source"`
	Started      string           `json:"started"`
	Ended        string           `json:"ended"`
	Summary      Summary          `json:"summary"`
	Stats        Stats            `json:"stats"`
	AccessPoints []AccessPoint    `json:"access_points"`
	Clients      []Client         `json:"clients"`
	Findings     []Finding        `json:"findings"`
	SAE          []SAEExchange    `json:"sae_exchanges"`
	Handshakes   []Handshake      `json:"handshakes"`
	EAPPwd       []EAPPwdExchange `json:"eap_pwd_exchanges"`
	ARP          []ARPMapping     `json:"arp_mappings"`
}

// Summary is the headline of a report.
type Summary struct {
	Severity string         `json:"severity"`
	Grade    string         `json:"grade"`
	Verdict  string         `json:"verdict"`
	Counts   map[string]int `json:"counts"`
	Findings int            `json:"findings"`
	APs      int            `json:"access_points"`
	Clients  int            `json:"clients"`
	Family   map[string]int `json:"by_family"`
}

// Stats mirrors the counters of the capture.
type Stats struct {
	Packets        int    `json:"packets"`
	Bytes          int    `json:"bytes"`
	Management     int    `json:"management"`
	Data           int    `json:"data"`
	Control        int    `json:"control"`
	Beacons        int    `json:"beacons"`
	ProbeRequests  int    `json:"probe_requests"`
	ProbeResponses int    `json:"probe_responses"`
	Auths          int    `json:"authentications"`
	Assocs         int    `json:"associations"`
	Deauths        int    `json:"deauthentications"`
	Disassocs      int    `json:"disassociations"`
	CSAs           int    `json:"channel_switch_announcements"`
	SAECommits     int    `json:"sae_commits"`
	SAEConfirms    int    `json:"sae_confirms"`
	EAPOLFrames    int    `json:"eapol_frames"`
	Handshakes     int    `json:"handshakes"`
	ARPPackets     int    `json:"arp_packets"`
	DHCPPackets    int    `json:"dhcp_packets"`
	DNSPackets     int    `json:"dns_packets"`
	Duration       string `json:"duration"`
}

// AccessPoint is one access point in the report.
type AccessPoint struct {
	BSSID     string   `json:"bssid"`
	SSID      string   `json:"ssid"`
	Hidden    bool     `json:"hidden"`
	Channel   int      `json:"channel"`
	Frequency int      `json:"frequency"`
	Signal    int      `json:"signal"`
	HasSignal bool     `json:"has_signal"`
	Beacons   int      `json:"beacons"`
	Probes    int      `json:"probe_responses"`
	Auths     int      `json:"authentications"`
	Assocs    int      `json:"associations"`
	Security  Security `json:"security"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Findings  int      `json:"findings"`
}

// Security is the posture of an access point in the report.
type Security struct {
	Open        bool     `json:"open"`
	WEP         bool     `json:"wep"`
	WPA1        bool     `json:"wpa1"`
	WPA2        bool     `json:"wpa2"`
	WPA3        bool     `json:"wpa3"`
	Transition  bool     `json:"transition"`
	OWE         bool     `json:"owe"`
	Enterprise  bool     `json:"enterprise"`
	MFPC        bool     `json:"mfpc"`
	MFPR        bool     `json:"mfpr"`
	SAEPK       bool     `json:"sae_pk"`
	AKMs        []string `json:"akm_suites"`
	Ciphers     []string `json:"pairwise_ciphers"`
	GroupCipher string   `json:"group_cipher"`
	Label       string   `json:"label"`
	Score       int      `json:"score"`
	Grade       string   `json:"grade"`
}

// Client is one station in the report.
type Client struct {
	MAC       string `json:"mac"`
	Frames    int    `json:"frames"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Findings  int    `json:"findings"`
}

// Finding is one security observation in the report.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Family   string `json:"family"`
	Target   string `json:"target"`
	Target2  string `json:"target_2,omitempty"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	Remedy   string `json:"remedy"`
	At       string `json:"at"`
}

// SAEExchange is one observed SAE handshake in the report.
type SAEExchange struct {
	BSSID    string  `json:"bssid"`
	Client   string  `json:"client"`
	GroupID  uint16  `json:"group_id"`
	Group    string  `json:"group"`
	Rating   string  `json:"rating"`
	Valid    bool    `json:"valid"`
	Checks   []Check `json:"checks"`
	AntiClog bool    `json:"anti_clogging_token"`
	Commits  int     `json:"commits"`
	Confirms int     `json:"confirms"`
	At       string  `json:"at"`
}

// Handshake is one observed four way handshake in the report.
type Handshake struct {
	BSSID    string `json:"bssid"`
	Client   string `json:"client"`
	Messages int    `json:"messages"`
	PMKID    string `json:"pmkid,omitempty"`
	Complete bool   `json:"complete"`
	At       string `json:"at"`
}

// EAPPwdExchange is one observed EAP-pwd exchange in the report.
type EAPPwdExchange struct {
	Server  string `json:"server"`
	Client  string `json:"client"`
	GroupID uint16 `json:"group_id"`
	Group   string `json:"group"`
	Rating  string `json:"rating"`
	Reflect bool   `json:"reflection"`
	Invalid bool   `json:"invalid"`
	At      string `json:"at"`
}

// ARPMapping is one address to hardware address mapping.
type ARPMapping struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Claims    int    `json:"claims"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// Check is one validation result.
type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// JSON renders the report as a JSON document.
func JSON(s *audit.Session) ([]byte, error) {
	return json.MarshalIndent(Build(s), "", "  ")
}

// Build turns a session into a report document.
func Build(s *audit.Session) Document {
	doc := Document{
		Tool:    "wyrm",
		Version: version.Get(),
		Source:  s.Source,
		Summary: buildSummary(s),
		Stats:   buildStats(s),
	}

	if !s.Started.IsZero() {
		doc.Started = s.Started.Format(time.RFC3339)
	}
	if !s.Ended.IsZero() {
		doc.Ended = s.Ended.Format(time.RFC3339)
	}

	for _, ap := range s.APList() {
		doc.AccessPoints = append(doc.AccessPoints, buildAP(ap))
	}
	for _, c := range s.ClientList() {
		doc.Clients = append(doc.Clients, buildClient(c))
	}
	for _, f := range s.Findings {
		doc.Findings = append(doc.Findings, buildFinding(f))
	}
	for _, ex := range s.SAE {
		doc.SAE = append(doc.SAE, buildSAE(ex))
	}
	for _, h := range s.Handshakes {
		doc.Handshakes = append(doc.Handshakes, buildHandshake(h))
	}
	for _, ex := range s.EAPPwd {
		doc.EAPPwd = append(doc.EAPPwd, buildEAPPwd(ex))
	}
	for _, ip := range sortedIPs(s.ARP) {
		m := s.ARP[ip]
		doc.ARP = append(doc.ARP, ARPMapping{
			IP:        m.IP,
			MAC:       m.MAC,
			Claims:    m.Claims,
			FirstSeen: stamp(m.FirstSeen),
			LastSeen:  stamp(m.LastSeen),
		})
	}
	return doc
}

func buildSummary(s *audit.Session) Summary {
	sev, grade := s.Overall()
	counts := s.CountBySeverity()
	bySeverity := map[string]int{}
	for _, level := range []audit.Severity{
		audit.SeverityCritical, audit.SeverityHigh, audit.SeverityMedium,
		audit.SeverityLow, audit.SeverityInfo,
	} {
		bySeverity[string(level)] = counts[level]
	}
	byFamily := map[string]int{}
	for _, f := range s.Findings {
		byFamily[f.Family]++
	}
	return Summary{
		Severity: string(sev),
		Grade:    grade,
		Verdict:  audit.GradeDescription(grade),
		Counts:   bySeverity,
		Findings: len(s.Findings),
		APs:      len(s.APs),
		Clients:  len(s.Clients),
		Family:   byFamily,
	}
}

func buildStats(s *audit.Session) Stats {
	st := s.Stats
	out := Stats{
		Packets:        st.Packets,
		Bytes:          st.Bytes,
		Management:     st.Management,
		Data:           st.Data,
		Control:        st.Control,
		Beacons:        st.Beacons,
		ProbeRequests:  st.ProbeRequests,
		ProbeResponses: st.ProbeResponses,
		Auths:          st.Auths,
		Assocs:         st.Assocs,
		Deauths:        st.Deauths,
		Disassocs:      st.Disassocs,
		CSAs:           st.CSAs,
		SAECommits:     st.SAECommits,
		SAEConfirms:    st.SAEConfirms,
		EAPOLFrames:    st.EAPOLFrames,
		Handshakes:     st.Handshakes,
		ARPPackets:     st.ARPPackets,
		DHCPPackets:    st.DHCPPackets,
		DNSPackets:     st.DNSPackets,
	}
	if !st.FirstSeen.IsZero() && st.LastSeen.After(st.FirstSeen) {
		out.Duration = st.LastSeen.Sub(st.FirstSeen).Round(time.Second).String()
	}
	return out
}

func buildAP(ap *audit.AP) AccessPoint {
	sec := ap.Security
	return AccessPoint{
		BSSID:     ap.BSSID,
		SSID:      ap.SSID,
		Hidden:    ap.Hidden,
		Channel:   ap.Channel,
		Frequency: ap.Frequency,
		Signal:    ap.Signal,
		HasSignal: ap.HasSignal,
		Beacons:   ap.Beacons,
		Probes:    ap.Probes,
		Auths:     ap.Auths,
		Assocs:    ap.Assocs,
		FirstSeen: stamp(ap.FirstSeen),
		LastSeen:  stamp(ap.LastSeen),
		Findings:  len(ap.Findings),
		Security: Security{
			Open:        sec.Open,
			WEP:         sec.WEP,
			WPA1:        sec.WPA1,
			WPA2:        sec.WPA2,
			WPA3:        sec.WPA3,
			Transition:  sec.Transition,
			OWE:         sec.OWE,
			Enterprise:  sec.Enterprise,
			MFPC:        sec.MFPC,
			MFPR:        sec.MFPR,
			SAEPK:       ap.SAEPKExclusively,
			AKMs:        nonNil(sec.AKMs),
			Ciphers:     nonNil(sec.Ciphers),
			GroupCipher: sec.GroupCipher,
			Label:       audit.DescribeSecurity(sec),
			Score:       sec.Score,
			Grade:       sec.Grade,
		},
	}
}

func buildClient(c *audit.Client) Client {
	return Client{
		MAC:       c.MAC,
		Frames:    c.Frames,
		FirstSeen: stamp(c.FirstSeen),
		LastSeen:  stamp(c.LastSeen),
		Findings:  len(c.Findings),
	}
}

func buildFinding(f audit.Finding) Finding {
	return Finding{
		ID:       f.ID,
		Title:    f.Title,
		Severity: string(f.Severity),
		Family:   f.Family,
		Target:   f.Target,
		Target2:  f.Target2,
		Detail:   f.Detail,
		Evidence: f.Evidence,
		Remedy:   f.Remedy,
		At:       stamp(f.At),
	}
}

func buildSAE(ex audit.SAEExchange) SAEExchange {
	out := SAEExchange{
		BSSID:    ex.BSSID,
		Client:   ex.Client,
		GroupID:  ex.GroupID,
		AntiClog: ex.Token,
		Commits:  ex.Commits,
		Confirms: ex.Confirms,
		At:       stamp(ex.At),
	}
	if ex.Group != nil {
		out.Group = ex.Group.Name
		out.Rating = ex.Group.Rating
	}
	if ex.Validation != nil {
		out.Valid = ex.Validation.Valid
		for _, c := range ex.Validation.Checks {
			out.Checks = append(out.Checks, Check{
				Name:     c.Name,
				OK:       c.Passed,
				Severity: c.Severity,
				Detail:   c.Detail,
			})
		}
	}
	return out
}

func buildHandshake(h audit.Handshake) Handshake {
	out := Handshake{
		BSSID:    h.BSSID,
		Client:   h.Client,
		Messages: h.Messages,
		Complete: h.Complete,
		At:       stamp(h.At),
	}
	if len(h.PMKID) > 0 {
		out.PMKID = fmt.Sprintf("%x", h.PMKID)
	}
	return out
}

func buildEAPPwd(ex audit.EAPPwdExchange) EAPPwdExchange {
	out := EAPPwdExchange{
		Server:  ex.Server,
		Client:  ex.Client,
		GroupID: ex.GroupID,
		Reflect: ex.Reflect,
		Invalid: ex.Invalid,
		At:      stamp(ex.At),
	}
	if ex.Group != nil {
		out.Group = ex.Group.Name
		out.Rating = ex.Group.Rating
	}
	return out
}

func sortedIPs(m map[string]*audit.ARPMapping) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// Text renders the report as plain text.
func Text(s *audit.Session) string {
	doc := Build(s)
	var b strings.Builder

	fmt.Fprintf(&b, "wyrm %s - wireless security audit\n", doc.Version.Version)
	fmt.Fprintf(&b, "source : %s\n", doc.Source)
	if doc.Started != "" {
		fmt.Fprintf(&b, "window : %s to %s", doc.Started, doc.Ended)
		if doc.Stats.Duration != "" {
			fmt.Fprintf(&b, " (%s)", doc.Stats.Duration)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	b.WriteString("SUMMARY\n")
	fmt.Fprintf(&b, "  verdict      : %s (%s)\n", doc.Summary.Grade, doc.Summary.Severity)
	fmt.Fprintf(&b, "  findings     : %d  (critical %d, high %d, medium %d, low %d, info %d)\n",
		doc.Summary.Findings,
		doc.Summary.Counts["critical"], doc.Summary.Counts["high"],
		doc.Summary.Counts["medium"], doc.Summary.Counts["low"], doc.Summary.Counts["info"])
	fmt.Fprintf(&b, "  access points: %d\n", doc.Summary.APs)
	fmt.Fprintf(&b, "  clients      : %d\n", doc.Summary.Clients)
	fmt.Fprintf(&b, "  packets      : %d\n", doc.Stats.Packets)
	for _, family := range audit.Families() {
		if n := doc.Summary.Family[family]; n > 0 {
			fmt.Fprintf(&b, "  %-13s: %d\n", family, n)
		}
	}

	b.WriteString("\nACCESS POINTS\n")
	if len(doc.AccessPoints) == 0 {
		b.WriteString("  none were seen\n")
	} else {
		fmt.Fprintf(&b, "  %-24s %-17s %3s  %-22s %-6s %s\n", "SSID", "BSSID", "CH", "SECURITY", "GRADE", "SIGNAL")
		for _, ap := range doc.AccessPoints {
			ssid := ap.SSID
			if ssid == "" {
				ssid = "<hidden>"
			}
			signal := ""
			if ap.HasSignal {
				signal = fmt.Sprintf("%d dBm", ap.Signal)
			}
			fmt.Fprintf(&b, "  %-24s %-17s %3d  %-22s %-6s %s\n",
				truncate(ssid, 24), ap.BSSID, ap.Channel,
				truncate(ap.Security.Label, 22), ap.Security.Grade, signal)
		}
	}

	if len(doc.SAE) > 0 {
		b.WriteString("\nSAE HANDSHAKES\n")
		for _, ex := range doc.SAE {
			state := "valid"
			if !ex.Valid {
				state = "INVALID"
			}
			fmt.Fprintf(&b, "  %s -> %s  group %s (%d)  %s  commits %d  confirms %d  token %v\n",
				ex.Client, ex.BSSID, ex.Group, ex.GroupID, state, ex.Commits, ex.Confirms, ex.AntiClog)
		}
	}

	if len(doc.Handshakes) > 0 {
		b.WriteString("\nWPA2 HANDSHAKES\n")
		for _, h := range doc.Handshakes {
			pmkid := ""
			if h.PMKID != "" {
				pmkid = "  pmkid " + h.PMKID
			}
			fmt.Fprintf(&b, "  %s -> %s  %d of 4 messages%s\n", h.Client, h.BSSID, h.Messages, pmkid)
		}
	}

	if len(doc.EAPPwd) > 0 {
		b.WriteString("\nEAP-PWD EXCHANGES\n")
		for _, ex := range doc.EAPPwd {
			fmt.Fprintf(&b, "  %s -> %s  group %s (%d)  reflection %v\n",
				ex.Client, ex.Server, ex.Group, ex.GroupID, ex.Reflect)
		}
	}

	b.WriteString("\nFINDINGS\n")
	if len(doc.Findings) == 0 {
		b.WriteString("  nothing was reported\n")
	}
	for _, f := range doc.Findings {
		fmt.Fprintf(&b, "  [%-8s] %-14s %s\n", strings.ToUpper(f.Severity), f.ID, f.Title)
		if f.Target != "" {
			fmt.Fprintf(&b, "      target   : %s\n", f.Target)
		}
		if f.Target2 != "" {
			fmt.Fprintf(&b, "      against  : %s\n", f.Target2)
		}
		if f.Detail != "" {
			fmt.Fprintf(&b, "      detail   : %s\n", f.Detail)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "      evidence : %s\n", f.Evidence)
		}
		if f.Remedy != "" {
			fmt.Fprintf(&b, "      remedy   : %s\n", f.Remedy)
		}
	}

	return b.String()
}

// truncate shortens a string to a maximum width.
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}
