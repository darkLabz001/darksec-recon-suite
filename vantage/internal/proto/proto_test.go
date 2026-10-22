package proto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	want := []string{
		"ajp13", "amqp", "bgp", "cassandra", "docker", "elasticsearch",
		"ftp", "http", "https", "imap", "imaps", "ipp", "irc", "kafka",
		"ldaps", "memcached", "mongodb", "msrpc", "mssql", "mysql", "netbios",
		"nfs", "ntp", "openvpn", "oracle", "pop3", "pop3s", "postgres",
		"printer", "redis", "rpcbind", "sip", "smb", "smtp", "smtps", "snmp",
		"socks", "ssh", "syslog", "telnet", "vnc", "xmpp", "zookeeper",
	}
	names := Names()
	for _, name := range want {
		if _, ok := Lookup(name); !ok {
			t.Errorf("the %q prober is not registered", name)
		}
	}
	if len(names) < len(want) {
		t.Errorf("only %d probers are registered, want at least %d", len(names), len(want))
	}
	for i := 1; i < len(names); i++ {
		if names[i] <= names[i-1] {
			t.Errorf("Names is not sorted: %q before %q", names[i-1], names[i])
			break
		}
	}
	if _, ok := Lookup("does-not-exist"); ok {
		t.Error("Lookup returned a prober for an unknown name")
	}
}

func TestCandidates(t *testing.T) {
	tests := []struct {
		port uint16
		want []string
	}{
		{22, []string{"ssh"}},
		{80, []string{"http"}},
		{443, []string{"https"}},
		{6379, []string{"redis"}},
		{5432, []string{"postgres"}},
	}
	for _, tt := range tests {
		got := Candidates(tt.port)
		if len(got) != len(tt.want) {
			t.Errorf("Candidates(%d) = %v, want %v", tt.port, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("Candidates(%d) = %v, want %v", tt.port, got, tt.want)
				break
			}
		}
	}
	if got := Candidates(65000); got != nil {
		t.Errorf("Candidates(65000) = %v, want nil", got)
	}
	if len(Known()) == 0 {
		t.Error("Known returned an empty map")
	}
}

func TestHTTPProber(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		body := "<html><head><title>vantage</title></head></html>"
		resp := "HTTP/1.1 200 OK\r\n" +
			"Server: nginx/1.24.0\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: " + itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
		_, _ = c.Write([]byte(resp))
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("http")
	obs, err := p.Probe(context.Background(), conn, ap, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if obs.Service != "http" {
		t.Errorf("service = %q, want http", obs.Service)
	}
	if obs.HTTP == nil {
		t.Fatal("the HTTP details are missing")
	}
	if obs.HTTP.Status != 200 {
		t.Errorf("status = %d, want 200", obs.HTTP.Status)
	}
	if obs.HTTP.Title != "vantage" {
		t.Errorf("title = %q, want vantage", obs.HTTP.Title)
	}
	if obs.Product != "nginx/1.24.0" {
		t.Errorf("product = %q", obs.Product)
	}
}

func TestHTTPProberRejectsGarbage(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		_, _ = c.Write([]byte("this is not http\r\n"))
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("http")
	if _, err := p.Probe(context.Background(), conn, ap, Options{Timeout: time.Second}); err == nil {
		t.Error("Probe accepted a non HTTP response")
	}
}

func TestSSHProber(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n"))
		time.Sleep(100 * time.Millisecond)
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("ssh")
	obs, err := p.Probe(context.Background(), conn, ap, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if obs.Service != "ssh" {
		t.Errorf("service = %q, want ssh", obs.Service)
	}
	if obs.Product != "OpenSSH" {
		t.Errorf("product = %q, want OpenSSH", obs.Product)
	}
	if obs.Version != "9.6p1" {
		t.Errorf("version = %q, want 9.6p1", obs.Version)
	}
}

func TestRedisProber(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		buf := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("+PONG\r\n$42\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n\r\n"))
		time.Sleep(100 * time.Millisecond)
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("redis")
	obs, err := p.Probe(context.Background(), conn, ap, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if obs.Service != "redis" {
		t.Errorf("service = %q, want redis", obs.Service)
	}
	if obs.Version != "7.2.4" {
		t.Errorf("version = %q, want 7.2.4", obs.Version)
	}
}

func TestMemcachedProber(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		buf := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("VERSION 1.6.21\r\n"))
		time.Sleep(100 * time.Millisecond)
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("memcached")
	obs, err := p.Probe(context.Background(), conn, ap, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if obs.Version != "1.6.21" {
		t.Errorf("version = %q, want 1.6.21", obs.Version)
	}
}

func TestNTPProber(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		buf := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf)
		resp := make([]byte, 48)
		resp[0] = 0x1c // LI 0, VN 4, Mode 4 (server)
		resp[1] = 2    // stratum
		_, _ = c.Write(resp)
		time.Sleep(100 * time.Millisecond)
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("ntp")
	obs, err := p.Probe(context.Background(), conn, ap, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if obs.Service != "ntp" {
		t.Errorf("service = %q, want ntp", obs.Service)
	}
	if obs.Extra != "stratum 2" {
		t.Errorf("extra = %q, want stratum 2", obs.Extra)
	}
}

func TestHTTPSProberAndJA3(t *testing.T) {
	cert := selfSignedCert(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		body := "<html><title>secure</title></html>"
		resp := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: " + itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
		_, _ = c.Write([]byte(resp))
	})

	ap := addrPort(t, ln)
	conn, err := net.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, _ := Lookup("https")
	obs, err := p.Probe(context.Background(), conn, ap, Options{
		Timeout:   3 * time.Second,
		EnableJA3: true,
	})
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if obs.Service != "https" {
		t.Errorf("service = %q, want https", obs.Service)
	}
	if obs.TLS == nil {
		t.Fatal("the TLS details are missing")
	}
	if !strings.HasPrefix(obs.TLS.Version, "TLS ") {
		t.Errorf("version = %q", obs.TLS.Version)
	}
	if obs.TLS.Subject == "" {
		t.Error("the certificate subject is missing")
	}
	if len(obs.JA3) != 32 {
		t.Errorf("JA3 = %q, want a 32 character digest", obs.JA3)
	}
	if _, err := hex.DecodeString(obs.JA3); err != nil {
		t.Errorf("JA3 is not hexadecimal: %v", err)
	}
	if len(obs.JA3S) != 32 {
		t.Errorf("JA3S = %q, want a 32 character digest", obs.JA3S)
	}
}

func TestJA3FromClientHello(t *testing.T) {
	// A ClientHello made of the standard fields: version 771, a random,
	// a session id, a cipher list and a few extensions.
	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00)       // session id length
	hello = append(hello, 0x00, 0x02) // cipher suite length
	hello = append(hello, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA
	hello = append(hello, 0x01, 0x00) // compression methods
	hello = append(hello, 0x00, 0x0e) // extensions length
	hello = append(hello, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
	hello = append(hello, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d)

	raw := tlsRecord(0x01, hello)

	got := ja3FromClientHello(raw)
	if len(got) != 32 {
		t.Fatalf("JA3 = %q, want a 32 character digest", got)
	}
	// The same input must always produce the same fingerprint.
	if again := ja3FromClientHello(raw); again != got {
		t.Error("the JA3 fingerprint is not deterministic")
	}
	if ja3FromClientHello(nil) != "" {
		t.Error("an empty buffer produced a JA3 fingerprint")
	}
}

func TestJA3SFromServerHello(t *testing.T) {
	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00)       // session id length
	hello = append(hello, 0x00, 0x2f) // cipher suite
	hello = append(hello, 0x00)       // compression method
	hello = append(hello, 0x00, 0x00) // extensions length

	raw := tlsRecord(0x02, hello)

	got := ja3sFromServerHello(raw)
	if len(got) != 32 {
		t.Fatalf("JA3S = %q, want a 32 character digest", got)
	}
	if ja3sFromServerHello(nil) != "" {
		t.Error("an empty buffer produced a JA3S fingerprint")
	}
}

func TestJA3IgnoresGREASEValues(t *testing.T) {
	// The same ClientHello, once with a GREASE cipher suite and a GREASE
	// extension and once without, must produce the same fingerprint.
	plain := []byte{0x03, 0x03}
	plain = append(plain, make([]byte, 32)...)
	plain = append(plain, 0x00)       // session id length
	plain = append(plain, 0x00, 0x02) // cipher suite length
	plain = append(plain, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA
	plain = append(plain, 0x01, 0x00) // compression methods
	plain = append(plain, 0x00, 0x0e) // extensions length
	plain = append(plain, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
	plain = append(plain, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d)

	greased := []byte{0x03, 0x03}
	greased = append(greased, make([]byte, 32)...)
	greased = append(greased, 0x00)                   // session id length
	greased = append(greased, 0x00, 0x06)             // cipher suite length
	greased = append(greased, 0x0a, 0x0a)             // GREASE cipher suite
	greased = append(greased, 0x00, 0x2f)             // TLS_RSA_WITH_AES_128_CBC_SHA
	greased = append(greased, 0x1a, 0x1a)             // GREASE cipher suite
	greased = append(greased, 0x01, 0x00)             // compression methods
	greased = append(greased, 0x00, 0x12)             // extensions length
	greased = append(greased, 0x0a, 0x0a, 0x00, 0x00) // GREASE extension
	greased = append(greased, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
	greased = append(greased, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d)

	if got, want := ja3FromClientHello(tlsRecord(0x01, greased)), ja3FromClientHello(tlsRecord(0x01, plain)); got != want {
		t.Errorf("the GREASE values changed the fingerprint: %q != %q", got, want)
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []int{0x0a0a, 0x1a1a, 0x2a2a, 0xaaaa, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	for _, v := range []int{0x0000, 0x002f, 0x1301, 0xc02f, 0x0b0a} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}

// tlsRecord wraps a handshake message in a TLS record.
func tlsRecord(msgType byte, body []byte) []byte {
	handshake := []byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func TestSplitProductVersion(t *testing.T) {
	tests := []struct {
		in          string
		wantProduct string
		wantVersion string
	}{
		{"OpenSSH_9.6p1", "OpenSSH", "9.6p1"},
		{"nginx/1.24.0", "nginx", "1.24.0"},
		{"Dropbear", "Dropbear", ""},
		{"  ", "", ""},
	}
	for _, tt := range tests {
		product, version := splitProductVersion(tt.in)
		if product != tt.wantProduct || version != tt.wantVersion {
			t.Errorf("splitProductVersion(%q) = %q, %q; want %q, %q",
				tt.in, product, version, tt.wantProduct, tt.wantVersion)
		}
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{"<html><head><title>Hello</title></head></html>", "Hello"},
		{"<TITLE>Upper</TITLE>", "Upper"},
		{"<title>  spaced   out  </title>", "spaced out"},
		{"<title>unterminated", ""},
		{"no title here", ""},
	}
	for _, tt := range tests {
		if got := extractTitle([]byte(tt.body)); got != tt.want {
			t.Errorf("extractTitle(%q) = %q, want %q", tt.body, got, tt.want)
		}
	}
}

func TestReadUntil(t *testing.T) {
	ln := listen(t)
	defer ln.Close()

	go serve(t, ln, func(c net.Conn) {
		_, _ = c.Write([]byte("hello\nworld\n"))
		time.Sleep(100 * time.Millisecond)
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	raw, err := readUntil(conn, 4096, hasLine)
	if err != nil {
		t.Fatalf("readUntil returned an error: %v", err)
	}
	if !strings.Contains(string(raw), "hello") {
		t.Errorf("readUntil returned %q", raw)
	}
}

func TestRecorderBoundsMemory(t *testing.T) {
	rec := newRecorder(&stubConn{})
	payload := make([]byte, 1024)
	for i := 0; i < 100; i++ {
		_, _ = rec.Write(payload)
	}
	if got := len(rec.WrittenBytes()); got != maxRecorded {
		t.Errorf("the recorder kept %d bytes, want the %d byte limit", got, maxRecorded)
	}
	if got := len(rec.ReadBytes()); got != 0 {
		t.Errorf("the recorder read %d bytes, want 0", got)
	}
}

func TestPostgresStartup(t *testing.T) {
	startup := postgresStartup("vantage_probe", "postgres")
	if len(startup) < 4 {
		t.Fatal("the startup message is too short")
	}
	length := int(startup[0])<<24 | int(startup[1])<<16 | int(startup[2])<<8 | int(startup[3])
	if length != len(startup) {
		t.Errorf("the declared length is %d, want %d", length, len(startup))
	}
	if !strings.Contains(string(startup), "vantage_probe") {
		t.Error("the startup message does not carry the user name")
	}
}

func TestMongoHello(t *testing.T) {
	doc := mongoHello()
	if len(doc) < 5 {
		t.Fatal("the hello message is too short")
	}
	length := int(doc[0])<<24 | int(doc[1])<<16 | int(doc[2])<<8 | int(doc[3])
	if length != len(doc) {
		t.Errorf("the declared length is %d, want %d", length, len(doc))
	}
	if !strings.Contains(string(doc), "$db") {
		t.Error("the hello message does not select a database")
	}
}

// stubConn is a net.Conn that discards everything written to it.
type stubConn struct{}

func (stubConn) Read([]byte) (int, error)    { return 0, nil }
func (stubConn) Write(p []byte) (int, error) { return len(p), nil }
func (stubConn) Close() error                { return nil }
func (stubConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (stubConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (stubConn) SetDeadline(time.Time) error { return nil }
func (stubConn) SetReadDeadline(time.Time) error {
	return nil
}
func (stubConn) SetWriteDeadline(time.Time) error {
	return nil
}

// TestEveryProberSurvivesGarbage feeds every registered prober a stream of
// bytes that means nothing to it.
//
// A prober that mis-parses a hostile or broken service must report an
// error, never panic and never hang.
func TestEveryProberSurvivesGarbage(t *testing.T) {
	garbage := []byte{
		0x00, 0xff, 0x13, 0x37, 0x00, 0x00, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x41, 0x42, 0x43, 0x44,
		0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	for _, name := range Names() {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ln := listen(t)
			defer ln.Close()

			go serve(t, ln, func(c net.Conn) {
				_, _ = c.Write(garbage)
				// Closing makes most probers fail fast instead of
				// waiting for their deadline.
				c.Close()
			})

			p, ok := Lookup(name)
			if !ok {
				t.Fatalf("the %q prober disappeared", name)
			}

			ap := addrPort(t, ln)
			conn, err := net.Dial("tcp", ap.String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			obs, err := p.Probe(ctx, conn, ap, Options{Timeout: 500 * time.Millisecond})
			if err == nil && obs == nil {
				t.Error("Probe returned neither an observation nor an error")
			}
			if err != nil && obs != nil {
				t.Error("Probe returned both an observation and an error")
			}
		})
	}
}

// TestEveryProberSurvivesSilence points every prober at a service that
// accepts the connection and then says nothing at all.
func TestEveryProberSurvivesSilence(t *testing.T) {
	for _, name := range Names() {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ln := listen(t)
			defer ln.Close()

			go serve(t, ln, func(c net.Conn) {
				time.Sleep(200 * time.Millisecond)
			})

			p, _ := Lookup(name)
			ap := addrPort(t, ln)
			conn, err := net.Dial("tcp", ap.String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			obs, err := p.Probe(ctx, conn, ap, Options{Timeout: 200 * time.Millisecond})
			if err == nil && obs == nil {
				t.Error("Probe returned neither an observation nor an error")
			}
		})
	}
}

// TestEveryProberHasAConsistentName checks the registry contract.
func TestEveryProberHasAConsistentName(t *testing.T) {
	for _, name := range Names() {
		p, _ := Lookup(name)
		if p.Name() != name {
			t.Errorf("the prober registered as %q calls itself %q", name, p.Name())
		}
		if p.Name() == "" {
			t.Error("a prober has an empty name")
		}
	}
}

// listen starts a loopback listener for the tests.
func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// addrPort returns the loopback address of a listener.
func addrPort(t *testing.T, ln net.Listener) netip.AddrPort {
	t.Helper()
	addr := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr(addr.IP.String()), uint16(addr.Port))
}

// serve accepts connections and runs the handler for each of them.
func serve(t *testing.T, ln net.Listener, fn func(net.Conn)) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fn(c)
			}(conn)
		}
	}()
}

// selfSignedCert builds a throwaway certificate for the TLS tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vantage.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"vantage.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// itoa renders a small integer.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func BenchmarkHTTPProbe(b *testing.B) {
	ln := listenB(b)
	defer ln.Close()

	go serveB(ln, func(c net.Conn) {
		body := "<html><head><title>vantage</title></head></html>"
		resp := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
		_, _ = c.Write([]byte(resp))
	})

	ap := addrPortB(ln)
	p, _ := Lookup("http")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", ap.String())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := p.Probe(context.Background(), conn, ap, Options{Timeout: 2 * time.Second}); err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

func listenB(b *testing.B) net.Listener {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	return ln
}

func addrPortB(ln net.Listener) netip.AddrPort {
	addr := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr(addr.IP.String()), uint16(addr.Port))
}

func serveB(ln net.Listener, fn func(net.Conn)) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fn(c)
			}(conn)
		}
	}()
}
