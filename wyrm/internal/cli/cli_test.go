package cli

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/pcap"
)

// ieee builds an IEEE OUI suite selector.
func ieee(t uint8) []byte { return []byte{0x00, 0x0F, 0xAC, t} }

// rsnElement builds the body of an RSN information element.
func rsnElement(group byte, pairwise, akms []byte, caps uint16) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00}) // version
	b.Write(ieee(group))
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], uint16(len(pairwise)))
	b.Write(n[:])
	for _, c := range pairwise {
		b.Write(ieee(c))
	}
	binary.LittleEndian.PutUint16(n[:], uint16(len(akms)))
	b.Write(n[:])
	for _, a := range akms {
		b.Write(ieee(a))
	}
	binary.LittleEndian.PutUint16(n[:], caps)
	b.Write(n[:])
	return b.Bytes()
}

// element wraps a body in an information element header.
func element(id uint8, body []byte) []byte {
	return append([]byte{id, uint8(len(body))}, body...)
}

// beacon builds a beacon frame.
func beacon(bssid []byte, ssid string, transition bool) []byte {
	frame := make([]byte, 24)
	frame[0] = byte(8<<4) | byte(0<<2) // management, beacon
	frame[1] = 0
	copy(frame[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[10:16], bssid)
	copy(frame[16:22], bssid)

	body := make([]byte, 12)
	binary.LittleEndian.PutUint64(body[0:8], 0x1122334455667788)
	binary.LittleEndian.PutUint16(body[8:10], 100)
	binary.LittleEndian.PutUint16(body[10:12], 0x0411)

	elements := element(0, []byte(ssid))
	elements = append(elements, element(3, []byte{0x06})...) // DS parameter set
	akms := []byte{0x08}                                     // SAE
	if transition {
		akms = []byte{0x02, 0x08} // PSK and SAE
	}
	elements = append(elements, element(48, rsnElement(0x04, []byte{0x04}, akms, 0x00C0))...)

	return append(frame, append(body, elements...)...)
}

// writeCapture writes a capture file with one beacon in it.
func writeCapture(t *testing.T, path string, frame []byte) {
	t.Helper()
	w, err := pcap.Create(path, pcap.LinkTypeIEEE80211, 65535)
	if err != nil {
		t.Fatalf("the writer must open: %v", err)
	}
	pkt := &pcap.Packet{Timestamp: time.Unix(1700000000, 0), Data: frame}
	if err := w.Write(pkt); err != nil {
		t.Fatalf("the packet must be written: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("the writer must close: %v", err)
	}
}

func TestRunWithoutArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(nil, &out, &errOut); code != ExitUsage {
		t.Errorf("the exit code reads %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(out.String(), "wyrm") {
		t.Error("the usage message is missing")
	}
}

func TestRunHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut); code != ExitOK {
		t.Errorf("the exit code reads %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Error("the usage message is missing")
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"version"}, &out, &errOut); code != ExitOK {
		t.Errorf("the exit code reads %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out.String(), "wyrm") {
		t.Error("the version message is missing")
	}
}

func TestRunWithAnUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"frobnicate"}, &out, &errOut); code != ExitUsage {
		t.Errorf("the exit code reads %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Error("the error message is missing")
	}
}

func TestAnalyze(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", true))

	var out, errOut bytes.Buffer
	if code := Run([]string{"analyze", path}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d, want %d: %s", code, ExitOK, errOut.String())
	}
	text := out.String()
	for _, want := range []string{"SUMMARY", "wyrm-net", "02:11:22:33:44:55", "WYM-DWN-005"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not mention %q", want)
		}
	}
}

func TestAnalyzeAsAJSONDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))

	var out, errOut bytes.Buffer
	if code := Run([]string{"analyze", path, "--format", "json"}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "\"tool\": \"wyrm\"") {
		t.Errorf("the report is not the expected JSON: %s", out.String())
	}
}

func TestAnalyzeAsAPage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))

	var out, errOut bytes.Buffer
	if code := Run([]string{"analyze", path, "--format", "html"}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d: %s", code, errOut.String())
	}
	if !strings.Contains(strings.ToLower(out.String()), "<!doctype html>") {
		t.Error("the report is not an HTML document")
	}
}

func TestAnalyzeWithABarePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))

	var out, errOut bytes.Buffer
	if code := Run([]string{path}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "wyrm-net") {
		t.Error("the report does not mention the access point")
	}
}

func TestAnalyzeWithoutAFile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"analyze"}, &out, &errOut); code != ExitError {
		t.Errorf("the exit code reads %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), "no capture file") {
		t.Error("the error message is missing")
	}
}

func TestAnalyzeWithAMissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"analyze", filepath.Join(t.TempDir(), "nope.pcap")}, &out, &errOut)
	if code != ExitError {
		t.Errorf("the exit code reads %d, want %d", code, ExitError)
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", true))

	var out, errOut bytes.Buffer
	if code := Run([]string{"check", path}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "WYM-DWN-005") {
		t.Errorf("the findings are missing: %s", out.String())
	}
	if !strings.Contains(out.String(), "remedy:") {
		t.Error("the findings carry no remedy")
	}
}

func TestCheckOfACleanCapture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))

	var out, errOut bytes.Buffer
	if code := Run([]string{"check", path}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d: %s", code, errOut.String())
	}
	if strings.Contains(out.String(), "WYM-DWN-001") {
		t.Errorf("a clean WPA3 network must not be reported as open: %s", out.String())
	}
}

func TestReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))
	outPath := filepath.Join(dir, "report.html")

	var out, errOut bytes.Buffer
	if code := Run([]string{"report", path, "-o", outPath, "--format", "html"}, &out, &errOut); code != ExitOK {
		t.Fatalf("the exit code reads %d: %s", code, errOut.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("the report must be written: %v", err)
	}
	if !strings.Contains(strings.ToLower(string(data)), "<!doctype html>") {
		t.Error("the report is not an HTML document")
	}
	if !strings.Contains(out.String(), outPath) {
		t.Error("the tool did not say where the report was written")
	}
}

func TestReportPicksTheFormatFromTheExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))

	cases := []struct {
		name  string
		ext   string
		check func(string) bool
	}{
		{"html", ".html", func(s string) bool {
			return strings.Contains(strings.ToLower(s), "<!doctype html>")
		}},
		{"json", ".json", func(s string) bool {
			return strings.HasPrefix(strings.TrimSpace(s), "{")
		}},
		{"text", ".txt", func(s string) bool {
			return strings.Contains(s, "SUMMARY")
		}},
	}
	for _, c := range cases {
		outPath := filepath.Join(dir, "report"+c.ext)
		var out, errOut bytes.Buffer
		if code := Run([]string{"report", path, "-o", outPath}, &out, &errOut); code != ExitOK {
			t.Fatalf("%s: the exit code reads %d: %s", c.name, code, errOut.String())
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("%s: the report must be written: %v", c.name, err)
		}
		if !c.check(string(data)) {
			t.Errorf("%s: the report was not written in that format", c.name)
		}
	}
}

func TestReportWithoutAnOutputFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))

	var out, errOut bytes.Buffer
	if code := Run([]string{"report", path}, &out, &errOut); code != ExitError {
		t.Errorf("the exit code reads %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), "no output file") {
		t.Error("the error message is missing")
	}
}

func TestReportWithAnUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	writeCapture(t, path, beacon([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "wyrm-net", false))
	outPath := filepath.Join(dir, "report.txt")

	var out, errOut bytes.Buffer
	code := Run([]string{"report", path, "-o", outPath, "--format", "pdf"}, &out, &errOut)
	if code != ExitError {
		t.Errorf("the exit code reads %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), "unknown format") {
		t.Error("the error message is missing")
	}
}

func TestSubcommandHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"analyze", "--help"}, &out, &errOut); code != ExitOK {
		t.Errorf("the exit code reads %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Error("the usage message is missing")
	}
}

func TestParseChannels(t *testing.T) {
	got, err := parseChannels("1,6,11")
	if err != nil {
		t.Fatalf("the channels must parse: %v", err)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 6 || got[2] != 11 {
		t.Errorf("the channels read %v", got)
	}

	got, err = parseChannels("36-48")
	if err != nil {
		t.Fatalf("the channels must parse: %v", err)
	}
	// The channels of the range that are not in use are skipped.
	if len(got) != 4 || got[0] != 36 || got[3] != 48 {
		t.Errorf("the channels read %v", got)
	}

	got, err = parseChannels(" 1 , 6 ")
	if err != nil {
		t.Fatalf("the channels must parse: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("the channels read %v", got)
	}
}

func TestParseChannelsRejectsBadInput(t *testing.T) {
	for _, spec := range []string{"", "  ", "abc", "1,abc", "0", "15", "1-", "-3", "1-2-3"} {
		if _, err := parseChannels(spec); err == nil {
			t.Errorf("the channel list %q must be rejected", spec)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate reads %q", got)
	}
	if got := truncate("hello world", 8); got != "hello w…" {
		t.Errorf("truncate reads %q", got)
	}
	if got := truncate("hello", 0); got != "" {
		t.Errorf("truncate reads %q", got)
	}
}
