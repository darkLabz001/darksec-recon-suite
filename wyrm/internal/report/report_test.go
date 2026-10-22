package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
)

// sample builds a session with one access point, one client, one SAE
// exchange, one handshake, one EAP-pwd exchange and one address mapping.
func sample() *audit.Session {
	s := audit.NewSession("capture.pcap")
	s.Started = time.Unix(1700000000, 0)
	s.Ended = time.Unix(1700000060, 0)

	ap := &audit.AP{
		BSSID:     "aa:bb:cc:dd:ee:ff",
		SSID:      "wyrm-net",
		Channel:   6,
		Frequency: 2437,
		Signal:    -42,
		HasSignal: true,
		Beacons:   12,
		Probes:    3,
		FirstSeen: time.Unix(1700000000, 0),
		LastSeen:  time.Unix(1700000060, 0),
		Security: audit.Security{
			WPA2:        true,
			WPA3:        true,
			Transition:  true,
			Personal:    true,
			MFPC:        true,
			MFPR:        true,
			AKMs:        []string{"PSK", "SAE"},
			Ciphers:     []string{"AES (CCM)"},
			GroupCipher: "AES (CCM)",
		},
	}
	ap.Security.Score = audit.ScoreSecurity(ap.Security, ap)
	s.APs[ap.BSSID] = ap

	s.Clients["11:22:33:44:55:66"] = &audit.Client{
		MAC:       "11:22:33:44:55:66",
		Frames:    42,
		FirstSeen: time.Unix(1700000005, 0),
		LastSeen:  time.Unix(1700000059, 0),
	}

	g, _ := dh.GroupByID(19)
	s.SAE = []audit.SAEExchange{{
		BSSID:    ap.BSSID,
		Client:   "11:22:33:44:55:66",
		GroupID:  19,
		Group:    g,
		Token:    true,
		Commits:  1,
		Confirms: 1,
		At:       time.Unix(1700000010, 0),
	}}

	s.Handshakes = []audit.Handshake{{
		BSSID:    ap.BSSID,
		Client:   "11:22:33:44:55:66",
		Messages: 4,
		Complete: true,
		At:       time.Unix(1700000015, 0),
	}}

	s.EAPPwd = []audit.EAPPwdExchange{{
		Server:  "aa:bb:cc:dd:ee:ff",
		Client:  "11:22:33:44:55:66",
		GroupID: 19,
		Group:   g,
		Reflect: true,
		At:      time.Unix(1700000020, 0),
	}}

	s.ARP["192.0.2.10"] = &audit.ARPMapping{
		IP:        "192.0.2.10",
		MAC:       "11:22:33:44:55:66",
		Claims:    2,
		FirstSeen: time.Unix(1700000030, 0),
		LastSeen:  time.Unix(1700000050, 0),
	}

	s.Stats = audit.Stats{
		Packets: 100, Bytes: 12345, Management: 60, Data: 40,
		Beacons: 12, ProbeRequests: 4, ProbeResponses: 3,
		SAECommits: 1, SAEConfirms: 1, EAPOLFrames: 8, Handshakes: 1,
		ARPPackets: 2, FirstSeen: s.Started, LastSeen: s.Ended,
	}

	audit.Run(s)
	return s
}

func TestBuild(t *testing.T) {
	doc := Build(sample())

	if doc.Tool != "wyrm" {
		t.Errorf("the tool reads %q", doc.Tool)
	}
	if doc.Source != "capture.pcap" {
		t.Errorf("the source reads %q", doc.Source)
	}
	if doc.Started == "" || doc.Ended == "" {
		t.Error("the report carries no timestamps")
	}
	if doc.Summary.APs != 1 {
		t.Errorf("the summary holds %d access points, want 1", doc.Summary.APs)
	}
	if doc.Summary.Clients != 1 {
		t.Errorf("the summary holds %d clients, want 1", doc.Summary.Clients)
	}
	if doc.Summary.Findings == 0 {
		t.Error("the report holds no findings")
	}
	if doc.Stats.Packets != 100 {
		t.Errorf("the report holds %d packets, want 100", doc.Stats.Packets)
	}
	if len(doc.AccessPoints) != 1 {
		t.Fatalf("the report holds %d access points, want 1", len(doc.AccessPoints))
	}
	if doc.AccessPoints[0].SSID != "wyrm-net" {
		t.Errorf("the access point reads %q", doc.AccessPoints[0].SSID)
	}
	if !doc.AccessPoints[0].Security.Transition {
		t.Error("the access point is in the transition mode")
	}
	if doc.AccessPoints[0].Security.Label == "" {
		t.Error("the access point carries no label")
	}
	if len(doc.SAE) != 1 {
		t.Fatalf("the report holds %d SAE exchanges, want 1", len(doc.SAE))
	}
	if doc.SAE[0].GroupID != 19 {
		t.Errorf("the SAE exchange holds the group %d, want 19", doc.SAE[0].GroupID)
	}
	if !doc.SAE[0].AntiClog {
		t.Error("the SAE exchange carried an anti-clogging token")
	}
	if len(doc.Handshakes) != 1 {
		t.Errorf("the report holds %d handshakes, want 1", len(doc.Handshakes))
	}
	if len(doc.EAPPwd) != 1 {
		t.Errorf("the report holds %d EAP-pwd exchanges, want 1", len(doc.EAPPwd))
	}
	if len(doc.ARP) != 1 {
		t.Errorf("the report holds %d address mappings, want 1", len(doc.ARP))
	}
	if doc.ARP[0].IP != "192.0.2.10" {
		t.Errorf("the address mapping reads %q", doc.ARP[0].IP)
	}
}

func TestJSON(t *testing.T) {
	raw, err := JSON(sample())
	if err != nil {
		t.Fatalf("the report must render: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the report must be valid JSON: %v", err)
	}
	if doc.Tool != "wyrm" {
		t.Errorf("the tool reads %q", doc.Tool)
	}
	if doc.Summary.APs != 1 {
		t.Errorf("the summary holds %d access points, want 1", doc.Summary.APs)
	}
	if !strings.Contains(string(raw), "\"access_points\"") {
		t.Error("the report carries no access point list")
	}
	if !strings.Contains(string(raw), "WYM-") {
		t.Error("the report carries no findings")
	}
}

func TestText(t *testing.T) {
	out := Text(sample())

	for _, want := range []string{
		"wyrm",
		"SUMMARY",
		"ACCESS POINTS",
		"wyrm-net",
		"aa:bb:cc:dd:ee:ff",
		"FINDINGS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q", want)
		}
	}
	if !strings.Contains(out, "WYM-DWN-005") {
		t.Error("the report does not mention the transition mode finding")
	}
}

func TestTextOfAnEmptySession(t *testing.T) {
	out := Text(audit.NewSession("empty.pcap"))
	if out == "" {
		t.Fatal("the report is empty")
	}
	if !strings.Contains(out, "none were seen") {
		t.Error("the report does not say that nothing was seen")
	}
}

func TestHTML(t *testing.T) {
	out, err := HTML(sample())
	if err != nil {
		t.Fatalf("the report must render: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "<!doctype html>") {
		t.Error("the report is not an HTML document")
	}
	if !strings.Contains(out, "wyrm-net") {
		t.Error("the report does not mention the access point")
	}
	if !strings.Contains(out, "</html>") {
		t.Error("the report is not closed")
	}
	// The page has to stand on its own, so it may not refer to a style
	// sheet or a script that lives somewhere else.
	if strings.Contains(out, "<link rel=\"stylesheet\"") {
		t.Error("the report refers to an external style sheet")
	}
	if strings.Contains(out, "src=\"http") {
		t.Error("the report loads something from the network")
	}
}

func TestHTMLOfAnEmptySession(t *testing.T) {
	out, err := HTML(audit.NewSession("empty.pcap"))
	if err != nil {
		t.Fatalf("the report must render: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "<!doctype html>") {
		t.Error("the report is not an HTML document")
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 0, ""},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.width); got != c.want {
			t.Errorf("truncate(%q, %d) reads %q, want %q", c.in, c.width, got, c.want)
		}
	}
	// A string that is too long is cut and marked with an ellipsis.
	got := truncate("hello world", 8)
	if len([]rune(got)) > 8 {
		t.Errorf("truncate read %q, which is longer than the width", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate read %q, which is not marked with an ellipsis", got)
	}
}
