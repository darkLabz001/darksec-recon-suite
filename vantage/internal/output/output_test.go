package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/engine"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/proto"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

func sampleResult() engine.Result {
	return engine.Result{
		Host:  target.Host{V4: netip.MustParseAddr("192.0.2.10")},
		Addr:  netip.MustParseAddr("192.0.2.10"),
		Port:  443,
		Proto: ports.TCP,
		State: engine.StateOpen,
		RTT:   12 * time.Millisecond,
		Service: &detect.ServiceInfo{
			Service:    "http",
			Product:    "nginx",
			Version:    "1.24.0",
			Extra:      "Example",
			CPE:        "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
			Banner:     "nginx/1.24.0",
			Confidence: 1,
			Method:     "probe",
			JA3:        "0123456789abcdef0123456789abcdef",
			JA3S:       "fedcba9876543210fedcba9876543210",
			Favicon:    "ZmF2aWNvbg==",
			TLS: &proto.TLSInfo{
				Version:     "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				ALPN:        "h2",
				Subject:     "CN=example.test",
				Issuer:      "CN=example.test",
				SelfSigned:  true,
				SANs:        []string{"example.test"},
				KeyType:     "ECDSA",
				SigAlg:      "ECDSA-SHA256",
			},
			HTTP: &proto.HTTPInfo{
				Status:      200,
				StatusText:  "OK",
				HTTPVersion: "HTTP/1.1",
				Title:       "Example",
				Server:      "nginx/1.24.0",
				ContentType: "text/html",
				Headers:     map[string]string{"Server": "nginx/1.24.0"},
				BodyBytes:   42,
			},
		},
	}
}

func write(t *testing.T, opts Options, results ...engine.Result) string {
	t.Helper()
	var buf bytes.Buffer
	opts.Output = &buf
	w, err := New(opts)
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}
	for _, res := range results {
		if err := w.Write(res); err != nil {
			t.Fatalf("Write returned an error: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	return buf.String()
}

func TestTextFormat(t *testing.T) {
	out := write(t, Options{Format: FormatText, NoColor: true}, sampleResult())
	if !strings.Contains(out, "192.0.2.10:443") {
		t.Errorf("the output does not carry the endpoint: %q", out)
	}
	if !strings.Contains(out, "open") {
		t.Errorf("the output does not carry the state: %q", out)
	}
	if !strings.Contains(out, "http") || !strings.Contains(out, "nginx") || !strings.Contains(out, "1.24.0") {
		t.Errorf("the output does not carry the service details: %q", out)
	}
	if !strings.Contains(out, "12.00ms") {
		t.Errorf("the output does not carry the round trip time: %q", out)
	}
}

func TestTextFormatColours(t *testing.T) {
	out := write(t, Options{Format: FormatText}, sampleResult())
	if !strings.Contains(out, "\x1b[32mopen\x1b[0m") {
		t.Errorf("the output is not coloured: %q", out)
	}
}

func TestTextFormatHidesClosedPorts(t *testing.T) {
	res := sampleResult()
	res.State = engine.StateClosed
	out := write(t, Options{Format: FormatText, NoColor: true}, res)
	if out != "" {
		t.Errorf("a closed port was rendered: %q", out)
	}

	out = write(t, Options{Format: FormatText, NoColor: true, ShowAll: true}, res)
	if !strings.Contains(out, "closed") {
		t.Errorf("the closed port was not rendered: %q", out)
	}
}

func TestJSONFormat(t *testing.T) {
	out := write(t, Options{Format: FormatJSON}, sampleResult())

	var docs []map[string]any
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("the output is not valid JSON: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("the output holds %d documents, want 1", len(docs))
	}
	doc := docs[0]
	if doc["ip"] != "192.0.2.10" {
		t.Errorf("ip = %v", doc["ip"])
	}
	if doc["port"].(float64) != 443 {
		t.Errorf("port = %v", doc["port"])
	}
	if doc["state"] != "open" {
		t.Errorf("state = %v", doc["state"])
	}
	if doc["product"] != "nginx" {
		t.Errorf("product = %v", doc["product"])
	}
	if doc["rtt_ms"].(float64) != 12 {
		t.Errorf("rtt_ms = %v", doc["rtt_ms"])
	}
	if _, ok := doc["tls"]; !ok {
		t.Error("the TLS details are missing")
	}
	if _, ok := doc["http"]; !ok {
		t.Error("the HTTP details are missing")
	}
}

func TestJSONFormatStreamsMultipleResults(t *testing.T) {
	out := write(t, Options{Format: FormatJSON}, sampleResult(), sampleResult(), sampleResult())

	var docs []map[string]any
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("the output is not valid JSON: %v", err)
	}
	if len(docs) != 3 {
		t.Fatalf("the output holds %d documents, want 3", len(docs))
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("the output is not an array: %q", out)
	}
}

func TestJSONFormatOfAnEmptyScan(t *testing.T) {
	out := write(t, Options{Format: FormatJSON})

	var docs []map[string]any
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("the output is not valid JSON: %v", err)
	}
	if len(docs) != 0 {
		t.Fatalf("the output holds %d documents, want none", len(docs))
	}
}

func TestJSONLFormat(t *testing.T) {
	out := write(t, Options{Format: FormatJSONL}, sampleResult(), sampleResult())

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("the output holds %d lines, want 2", len(lines))
	}
	for _, line := range lines {
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			t.Fatalf("a line is not valid JSON: %v", err)
		}
	}
}

func TestCSVFormat(t *testing.T) {
	out := write(t, Options{Format: FormatCSV}, sampleResult())

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("the output is not valid CSV: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("the output holds %d records, want 2", len(records))
	}
	header := records[0]
	if header[0] != "ip" || header[1] != "port" || header[2] != "protocol" {
		t.Errorf("unexpected header: %v", header)
	}
	row := records[1]
	if row[0] != "192.0.2.10" || row[1] != "443" || row[2] != "tcp" {
		t.Errorf("unexpected row: %v", row)
	}
	if row[4] != "http" || row[5] != "nginx" || row[6] != "1.24.0" {
		t.Errorf("unexpected row: %v", row)
	}
}

func TestGreppableFormat(t *testing.T) {
	out := write(t, Options{Format: FormatGreppable}, sampleResult())
	line := strings.TrimSpace(out)
	if line != "192.0.2.10:443 http nginx 1.24.0" {
		t.Errorf("greppable output = %q", line)
	}

	closed := sampleResult()
	closed.State = engine.StateClosed
	if out := write(t, Options{Format: FormatGreppable}, closed); out != "" {
		t.Errorf("a closed port was rendered: %q", out)
	}
}

func TestTemplateFormat(t *testing.T) {
	tmpl := "{{.Endpoint}} {{.Service}} {{.Product}} {{.Version}} {{upper .State}}"
	out := write(t, Options{Format: FormatTemplate, Template: tmpl}, sampleResult())
	if strings.TrimSpace(out) != "192.0.2.10:443 http nginx 1.24.0 OPEN" {
		t.Errorf("template output = %q", out)
	}
}

func TestTemplateFormatErrors(t *testing.T) {
	var buf bytes.Buffer
	if _, err := New(Options{Format: FormatTemplate, Output: &buf}); err == nil {
		t.Error("New accepted a template format without a template")
	}
	if _, err := New(Options{Format: FormatTemplate, Template: "{{", Output: &buf}); err == nil {
		t.Error("New accepted an invalid template")
	}
}

func TestUnknownFormatFallsBackToText(t *testing.T) {
	out := write(t, Options{Format: "nonsense", NoColor: true}, sampleResult())
	if !strings.Contains(out, "192.0.2.10:443") {
		t.Errorf("the output = %q", out)
	}
}

func TestEmptyResult(t *testing.T) {
	res := engine.Result{
		Addr:  netip.MustParseAddr("198.51.100.5"),
		Port:  8080,
		Proto: ports.UDP,
		State: engine.StateFiltered,
	}
	out := write(t, Options{Format: FormatJSON}, res)
	var docs []map[string]any
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("the output is not valid JSON: %v", err)
	}
	if _, ok := docs[0]["service"]; ok {
		t.Error("an empty service was rendered")
	}
}

func BenchmarkWriteJSON(b *testing.B) {
	var buf bytes.Buffer
	w, err := New(Options{Format: FormatJSON, Output: &buf})
	if err != nil {
		b.Fatal(err)
	}
	res := sampleResult()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(res); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteText(b *testing.B) {
	var buf bytes.Buffer
	w, err := New(Options{Format: FormatText, Output: &buf})
	if err != nil {
		b.Fatal(err)
	}
	res := sampleResult()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(res); err != nil {
			b.Fatal(err)
		}
	}
}
