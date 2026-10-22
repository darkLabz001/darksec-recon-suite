package detect

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRuleMatch(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantService string
		wantProduct string
		wantVersion string
	}{
		{"openssh", "SSH-2.0-OpenSSH_9.6p1 Debian-3", "ssh", "OpenSSH", "9.6p1"},
		{"dropbear", "SSH-2.0-dropbear_2022.83", "ssh", "Dropbear SSH", "2022.83"},
		{"nginx", "Server: nginx/1.24.0\r\n", "http", "nginx", "1.24.0"},
		{"apache", "Server: Apache/2.4.52 (Ubuntu)", "http", "Apache HTTP Server", "2.4.52"},
		{"iis", "Server: Microsoft-IIS/10.0", "http", "Microsoft IIS", "10.0"},
		{"postgres", "PostgreSQL 15.4 on x86_64", "postgres", "PostgreSQL", "15.4"},
		{"redis", "redis_version:7.2.4\r\nredis_mode:standalone\r\n", "redis", "Redis", "7.2.4"},
		{"memcached", "VERSION 1.6.21", "memcached", "Memcached", "1.6.21"},
		{"mysql", "8.0.32-0ubuntu0.22.04.1", "mysql", "MySQL", "8.0.32"},
		{"docker", "{\"Version\":\"24.0.7\",\"ApiVersion\":\"1.43\"}", "docker", "Docker", "24.0.7"},
		{"grafana", "X-Grafana-Instance: Grafana v10.1.2", "http", "Grafana", ""},
		{"unknown", "something entirely different", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &ServiceInfo{}
			matched := false
			for _, rule := range Rules(nil) {
				if rule.Match(tt.banner, info) {
					matched = true
					break
				}
			}
			if tt.wantProduct == "" {
				if matched {
					t.Fatalf("the banner matched a rule: %+v", info)
				}
				return
			}
			if !matched {
				t.Fatal("the banner did not match any rule")
			}
			if info.Product != tt.wantProduct {
				t.Errorf("product = %q, want %q", info.Product, tt.wantProduct)
			}
			if info.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", info.Version, tt.wantVersion)
			}
			if info.CPE == "" {
				t.Error("the rule did not produce a CPE identifier")
			}
		})
	}
}

func TestRuleVersionFillsCPE(t *testing.T) {
	rule := Rule{
		Name:         "test",
		Service:      "http",
		Pattern:      mustCompile(`Demo/([0-9.]+)`),
		Product:      "Demo",
		VersionGroup: 1,
		CPE:          "cpe:2.3:a:demo:demo:%s:*:*:*:*:*:*:*",
	}
	info := &ServiceInfo{}
	if !rule.Match("Server: Demo/3.1", info) {
		t.Fatal("the rule did not match")
	}
	if info.Version != "3.1" {
		t.Fatalf("version = %q, want 3.1", info.Version)
	}
	if info.CPE != "cpe:2.3:a:demo:demo:3.1:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q", info.CPE)
	}
}

func TestRuleProductGroupFallback(t *testing.T) {
	rule := Rule{
		Name:         "test",
		Service:      "http",
		Pattern:      mustCompile(`^([A-Za-z]+)/([0-9.]+)`),
		ProductGroup: 1,
		VersionGroup: 2,
	}
	info := &ServiceInfo{}
	if !rule.Match("Widget/2.0 ready", info) {
		t.Fatal("the rule did not match")
	}
	if info.Product != "Widget" {
		t.Errorf("product = %q, want Widget", info.Product)
	}
	if info.Version != "2.0" {
		t.Errorf("version = %q, want 2.0", info.Version)
	}
}

func TestFingerprint(t *testing.T) {
	d := New(Config{})

	info := d.Fingerprint("SSH-2.0-OpenSSH_9.6p1 Debian-3")
	if info == nil {
		t.Fatal("Fingerprint returned nothing")
	}
	if info.Service != "ssh" {
		t.Errorf("service = %q, want ssh", info.Service)
	}
	if info.Product != "OpenSSH" {
		t.Errorf("product = %q, want OpenSSH", info.Product)
	}
	if info.Version != "9.6p1" {
		t.Errorf("version = %q, want 9.6p1", info.Version)
	}
	if info.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1", info.Confidence)
	}
	if info.Method != "fingerprint" {
		t.Errorf("method = %q, want fingerprint", info.Method)
	}
}

func TestFingerprintUnknown(t *testing.T) {
	d := New(Config{})
	if info := d.Fingerprint("nothing recognisable here"); info != nil {
		t.Errorf("Fingerprint returned %+v, want nil", info)
	}
	if info := d.Fingerprint(""); info != nil {
		t.Errorf("Fingerprint returned %+v for an empty banner, want nil", info)
	}
}

func TestCustomRulesExtendDatabase(t *testing.T) {
	d := New(Config{
		Rules: []Rule{{
			Name:         "acme",
			Service:      "http",
			Pattern:      mustCompile(`AcmeServer/([0-9.]+)`),
			Product:      "Acme Server",
			VersionGroup: 1,
		}},
	})

	info := d.Fingerprint("X-Powered-By: AcmeServer/7.7")
	if info == nil {
		t.Fatal("the custom rule did not match")
	}
	if info.Product != "Acme Server" {
		t.Errorf("product = %q", info.Product)
	}
	if info.Version != "7.7" {
		t.Errorf("version = %q", info.Version)
	}
}

func TestLoadRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `{
	  "rules": [
	    {
	      "name": "acme",
	      "service": "http",
	      "pattern": "AcmeServer/([0-9.]+)",
	      "product": "Acme Server",
	      "version_group": 1,
	      "cpe": "cpe:2.3:a:acme:acme_server:%s:*:*:*:*:*:*:*"
	    }
	  ]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules returned an error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Name != "acme" || rule.Service != "http" || rule.Product != "Acme Server" {
		t.Errorf("unexpected rule: %+v", rule)
	}
	if rule.VersionGroup != 1 {
		t.Errorf("version group = %d, want 1", rule.VersionGroup)
	}

	info := &ServiceInfo{}
	if !rule.Match("AcmeServer/1.2", info) {
		t.Fatal("the loaded rule did not match")
	}
	if info.Version != "1.2" {
		t.Errorf("version = %q, want 1.2", info.Version)
	}
}

func TestLoadRulesErrors(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "missing.json")
	if _, err := LoadRules(missing); err == nil {
		t.Error("LoadRules accepted a missing file")
	}

	noPattern := filepath.Join(dir, "nopattern.json")
	if err := os.WriteFile(noPattern, []byte(`{"rules":[{"name":"x"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(noPattern); err == nil {
		t.Error("LoadRules accepted a rule without a pattern")
	}

	badPattern := filepath.Join(dir, "badpattern.json")
	if err := os.WriteFile(badPattern, []byte(`{"rules":[{"name":"x","pattern":"("}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(badPattern); err == nil {
		t.Error("LoadRules accepted an invalid regular expression")
	}

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(badJSON); err == nil {
		t.Error("LoadRules accepted malformed JSON")
	}
}

func TestDetectHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
				body := "<html><head><title>Example</title></head><body>hi</body></html>"
				resp := "HTTP/1.1 200 OK\r\n" +
					"Server: nginx/1.24.0\r\n" +
					"Content-Type: text/html\r\n" +
					"Content-Length: " + itoa(int64(len(body))) + "\r\n" +
					"Connection: close\r\n\r\n" + body
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr(addr.IP.String()), uint16(addr.Port))

	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}

	d := New(Config{Timeout: 2 * time.Second, BannerTimeout: time.Second, EnableHTTP: true})
	info := d.Detect(context.Background(), ap, conn, nil)
	if info == nil {
		t.Fatal("Detect returned nothing")
	}
	if info.Service != "http" {
		t.Errorf("service = %q, want http", info.Service)
	}
	if info.HTTP == nil {
		t.Fatal("the HTTP details were not collected")
	}
	if info.HTTP.Status != 200 {
		t.Errorf("status = %d, want 200", info.HTTP.Status)
	}
	if info.HTTP.Server != "nginx/1.24.0" {
		t.Errorf("server header = %q", info.HTTP.Server)
	}
	if info.HTTP.Title != "Example" {
		t.Errorf("title = %q, want Example", info.HTTP.Title)
	}
	if info.Product != "nginx" {
		t.Errorf("product = %q, want nginx", info.Product)
	}
	if info.Version != "1.24.0" {
		t.Errorf("version = %q, want 1.24.0", info.Version)
	}
}

func TestDetectCollectsTheFavicon(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	icon := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if strings.Contains(string(buf[:n]), "/favicon.ico") {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\nContent-Length: " +
						itoa(int64(len(icon))) + "\r\nConnection: close\r\n\r\n"))
					_, _ = c.Write(icon)
					return
				}
				body := "<html><head><title>Example</title></head></html>"
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: " +
					itoa(int64(len(body))) + "\r\nConnection: close\r\n\r\n" + body))
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr(addr.IP.String()), uint16(addr.Port))

	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}

	d := New(Config{
		Timeout:       2 * time.Second,
		BannerTimeout: time.Second,
		EnableHTTP:    true,
		EnableFavicon: true,
	})
	info := d.Detect(context.Background(), ap, conn, nil)
	if info == nil {
		t.Fatal("Detect returned nothing")
	}
	if info.Favicon == "" {
		t.Fatal("the favicon fingerprint was not collected")
	}
	if want := FaviconHash(icon); info.Favicon != want {
		t.Errorf("favicon = %q, want %q", info.Favicon, want)
	}
}

func TestDetectBannerFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr(addr.IP.String()), uint16(addr.Port))

	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}

	d := New(Config{
		Timeout:       time.Second,
		BannerTimeout: time.Second,
		EnableHTTP:    true,
		Protocols:     []string{"ssh"},
	})
	info := d.Detect(context.Background(), ap, conn, nil)
	if info == nil {
		t.Fatal("Detect returned nothing")
	}
	if info.Product != "OpenSSH" {
		t.Errorf("product = %q, want OpenSSH", info.Product)
	}
	if !strings.Contains(info.Banner, "OpenSSH") {
		t.Errorf("banner = %q", info.Banner)
	}
}

func TestDetectNilConnection(t *testing.T) {
	d := New(Config{})
	if info := d.Detect(context.Background(), netip.AddrPort{}, nil, nil); info != nil {
		t.Errorf("Detect returned %+v for a nil connection, want nil", info)
	}
}

func mustCompile(expr string) *regexp.Regexp {
	return regexp.MustCompile(expr)
}

func TestEmptyServiceInfo(t *testing.T) {
	var s *ServiceInfo
	if !s.Empty() {
		t.Error("a nil ServiceInfo should be empty")
	}
	if (&ServiceInfo{}).Empty() != true {
		t.Error("an empty ServiceInfo should report empty")
	}
	if (&ServiceInfo{Service: "http"}).Empty() {
		t.Error("a populated ServiceInfo should not report empty")
	}
}
