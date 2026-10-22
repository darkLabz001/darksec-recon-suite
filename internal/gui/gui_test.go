package gui

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// listenTCP opens a loopback listener that accepts and immediately closes
// every connection, and returns its port.
func listenTCP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitFor polls the manager until the predicate is satisfied or the scan
// finishes without it.
func waitFor(t *testing.T, m *manager, pred func(statsJSON) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := m.stats()
		if pred(st) {
			return
		}
		if !st.Running && st.Done > 0 {
			t.Fatalf("scan finished before the condition held: %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition did not hold in time: %+v", m.stats())
}

func do(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestInfo(t *testing.T) {
	s, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := do(t, s, http.MethodGet, "/api/info", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var info map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := info["version"]; !ok {
		t.Error("the info response has no version")
	}
	if _, ok := info["syn_available"]; !ok {
		t.Error("the info response has no syn_available")
	}
}

func TestServeIndex(t *testing.T) {
	s, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := do(t, s, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "vantage") {
		t.Error("the index does not mention vantage")
	}
}

func TestScanRejectsBadRequest(t *testing.T) {
	s, _ := NewServer()
	rec := do(t, s, http.MethodPost, "/api/scan", "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestScanRejectsNoTargets(t *testing.T) {
	s, _ := NewServer()
	rec := do(t, s, http.MethodPost, "/api/scan", `{"targets":"","ports":"80"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("an empty target set produced no error")
	}
}

func TestScanOpenPort(t *testing.T) {
	port := listenTCP(t)
	s, _ := NewServer()

	body := `{"targets":"127.0.0.1","ports":"` + strconv.Itoa(port) + `","engine":"connect","detect":false}`
	rec := do(t, s, http.MethodPost, "/api/scan", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}

	waitFor(t, s.mgr, func(st statsJSON) bool { return st.Open == 1 })

	st := s.mgr.stats()
	if st.Total != 1 {
		t.Errorf("total = %d, want 1", st.Total)
	}
	if st.Done != 1 {
		t.Errorf("done = %d, want 1", st.Done)
	}

	s.mgr.mu.Lock()
	if len(s.mgr.results) != 1 {
		t.Fatalf("%d results, want 1", len(s.mgr.results))
	}
	res := s.mgr.results[0]
	s.mgr.mu.Unlock()
	if res.State != "open" {
		t.Errorf("state = %q, want open", res.State)
	}
	if int(res.Port) != port {
		t.Errorf("port = %d, want %d", res.Port, port)
	}
}

func TestScanClosedPort(t *testing.T) {
	// Reserve a port and then close it so that nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	s, _ := NewServer()
	body := `{"targets":"127.0.0.1","ports":"` + strconv.Itoa(port) + `","engine":"connect","detect":false}`
	rec := do(t, s, http.MethodPost, "/api/scan", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	waitFor(t, s.mgr, func(st statsJSON) bool { return st.Closed == 1 })
}

func TestStopScan(t *testing.T) {
	s, _ := NewServer()
	rec := do(t, s, http.MethodPost, "/api/stop", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestExportCSV(t *testing.T) {
	port := listenTCP(t)
	s, _ := NewServer()

	body := `{"targets":"127.0.0.1","ports":"` + strconv.Itoa(port) + `","engine":"connect","detect":false}`
	if rec := do(t, s, http.MethodPost, "/api/scan", body); rec.Code != http.StatusAccepted {
		t.Fatalf("scan: %d", rec.Code)
	}
	waitFor(t, s.mgr, func(st statsJSON) bool { return st.Open == 1 })

	rec := do(t, s, http.MethodGet, "/api/export?format=csv", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("the CSV export has %d lines, want a header and a row", len(lines))
	}
	if !strings.HasPrefix(lines[0], "ip,port,protocol,state") {
		t.Errorf("the CSV header is %q", lines[0])
	}
}

func TestExportJSON(t *testing.T) {
	port := listenTCP(t)
	s, _ := NewServer()

	body := `{"targets":"127.0.0.1","ports":"` + strconv.Itoa(port) + `","engine":"connect","detect":false}`
	_ = do(t, s, http.MethodPost, "/api/scan", body)
	waitFor(t, s.mgr, func(st statsJSON) bool { return st.Open == 1 })

	rec := do(t, s, http.MethodGet, "/api/export?format=json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var results []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("the JSON export is not an array: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the JSON export has %d results, want 1", len(results))
	}
}

func TestBuildPortList(t *testing.T) {
	cases := []struct {
		req  scanRequest
		udp  bool
		want int
	}{
		{scanRequest{Ports: "80,443"}, false, 2},
		{scanRequest{Ports: "1-1000"}, false, 1000},
		{scanRequest{TopPorts: 10}, false, 10},
		{scanRequest{TopPorts: 10}, true, 10},
		{scanRequest{Ports: "U:53,67"}, true, 2},
		{scanRequest{Ports: "53"}, true, 1}, // bare spec is UDP in UDP mode
		{scanRequest{}, false, 1000},        // default
		{scanRequest{}, true, 44},           // default UDP (the bundled list length)
	}
	for _, c := range cases {
		got, err := buildPortList(c.req, c.udp)
		if err != nil {
			t.Fatalf("buildPortList(%+v, %v): %v", c.req, c.udp, err)
		}
		if len(got) != c.want {
			t.Errorf("buildPortList(%+v, %v) = %d ports, want %d", c.req, c.udp, len(got), c.want)
		}
	}
}

func TestBuildPortListRejectsBadSpec(t *testing.T) {
	if _, err := buildPortList(scanRequest{Ports: "not-a-port"}, false); err == nil {
		t.Error("a bogus port specification was accepted")
	}
}

func TestSplitFields(t *testing.T) {
	got := splitFields(" 127.0.0.1, 10.0.0.1\texample.com\n")
	want := []string{"127.0.0.1", "10.0.0.1", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("splitFields returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitFields[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBrowserURL(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8787":   "http://127.0.0.1:8787/",
		"0.0.0.0:8787":     "http://127.0.0.1:8787/",
		":8787":            "http://127.0.0.1:8787/",
		"localhost:9090":   "http://localhost:9090/",
		"[::1]:8787":       "http://[::1]:8787/",
		"192.168.1.5:8080": "http://192.168.1.5:8080/",
	}
	for in, want := range cases {
		if got := browserURL(in); got != want {
			t.Errorf("browserURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	_, err = net.Listen("tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("a second listener on the same address did not fail")
	}
	if !isAddrInUse(err) {
		t.Errorf("the error %v was not recognised as address-in-use", err)
	}
}
