package proto

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// exchange writes a payload and reads the reply.
func exchange(c net.Conn, payload []byte, timeout time.Duration, max int) ([]byte, error) {
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.Write(payload); err != nil {
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	return readUntil(c, max, nil)
}

// mysqlProber reads the server greeting packet.
type mysqlProber struct{}

func (mysqlProber) Name() string   { return "mysql" }
func (mysqlProber) Greeting() bool { return true }

func (mysqlProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	header := make([]byte, 4)
	if _, err := io.ReadFull(rec, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	if length <= 0 || length > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(rec, payload); err != nil {
		return nil, err
	}
	if len(payload) < 2 {
		return nil, io.ErrUnexpectedEOF
	}

	version := ""
	if idx := indexByte(payload[1:], 0); idx >= 0 {
		version = string(payload[1 : 1+idx])
	}

	obs := &Observation{
		Service: "mysql",
		Product: "mysql",
		Version: version,
		Raw:     append(header, payload...),
	}
	if plugin := mysqlAuthPlugin(payload); plugin != "" {
		obs.Extra = plugin
	}
	return obs, nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func mysqlAuthPlugin(payload []byte) string {
	// The authentication plugin name is the last NUL terminated string of
	// the handshake packet.
	end := len(payload) - 1
	for end > 0 && payload[end] != 0 {
		end--
	}
	if end == 0 {
		return ""
	}
	start := end - 1
	for start > 0 && payload[start] != 0 {
		start--
	}
	return string(payload[start+1 : end])
}

func init() { Register(mysqlProber{}) }

// postgresProber negotiates SSL support and reads the server parameters.
type postgresProber struct{}

func (postgresProber) Name() string   { return "postgres" }
func (postgresProber) Greeting() bool { return false }

func (postgresProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)

	// SSLRequest: length 8, request code 80877103.
	sslReq := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write(sslReq); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	resp := make([]byte, 1)
	if _, err := io.ReadFull(rec, resp); err != nil {
		return nil, err
	}
	if resp[0] != 'S' && resp[0] != 'N' {
		return nil, io.ErrUnexpectedEOF
	}
	if resp[0] == 'S' {
		// The server accepts TLS but we asked for a plaintext session.
		return &Observation{Service: "postgres", Product: "postgres", Extra: "ssl", Raw: resp}, nil
	}

	// The server refused SSL, so send a startup message with a probe user
	// name that will not match a real account.
	startup := postgresStartup("vantage_probe", "postgres")
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write(startup); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	obs := &Observation{Service: "postgres", Product: "postgres"}
	buf := make([]byte, 4096)
	for i := 0; i < 8; i++ {
		n, err := rec.Read(buf)
		if n > 0 {
			obs.Raw = append(obs.Raw, buf[:n]...)
			if v := postgresParam(obs.Raw, "server_version"); v != "" {
				obs.Version = v
				obs.Extra = "ssl"
				return obs, nil
			}
			if postgresIsError(obs.Raw) {
				return obs, nil
			}
		}
		if err != nil {
			break
		}
	}
	return obs, nil
}

// postgresStartup builds a PostgreSQL StartupMessage.
func postgresStartup(user, database string) []byte {
	body := make([]byte, 0, 64)
	body = append(body, 0, 0, 0, 0)             // placeholder for length
	body = append(body, 0x00, 0x03, 0x00, 0x00) // protocol version 3.0
	body = append(body, "user\x00"...)
	body = append(body, user...)
	body = append(body, 0)
	body = append(body, "database\x00"...)
	body = append(body, database...)
	body = append(body, 0)
	body = append(body, 0) // terminator
	binary.BigEndian.PutUint32(body[0:4], uint32(len(body)))
	return body
}

// postgresParam extracts a backend parameter from a backend message stream.
func postgresParam(raw []byte, name string) string {
	idx := indexBytes(raw, []byte(name+"\x00"))
	if idx < 0 {
		return ""
	}
	rest := raw[idx+len(name)+1:]
	if len(rest) == 0 {
		return ""
	}
	size := int(rest[0])
	if size <= 0 || size > len(rest)-1 {
		return ""
	}
	return string(rest[1 : 1+size])
}

// postgresIsError reports whether the stream contains an ErrorResponse.
func postgresIsError(raw []byte) bool { return indexBytes(raw, []byte("SERROR")) >= 0 }

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func init() { Register(postgresProber{}) }

// redisProber issues PING and INFO.
type redisProber struct{}

func (redisProber) Name() string   { return "redis" }
func (redisProber) Greeting() bool { return false }

func (redisProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	payload := []byte("PING\r\nINFO server\r\n")
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write(payload); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	raw, err := readUntil(rec, 8192, nil)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}

	text := string(raw)
	if !strings.Contains(text, "PONG") && !strings.Contains(text, "redis_version") &&
		!strings.Contains(text, "NOAUTH") && !strings.Contains(text, "DENIED") &&
		!strings.Contains(text, "LOADING") {
		return nil, io.ErrUnexpectedEOF
	}

	obs := &Observation{Service: "redis", Product: "redis", Raw: raw}
	if m := regexp.MustCompile(`redis_version:([0-9][0-9A-Za-z.\-]*)`).FindStringSubmatch(text); m != nil {
		obs.Version = m[1]
	}
	if m := regexp.MustCompile(`redis_mode:([a-z]+)`).FindStringSubmatch(text); m != nil {
		obs.Extra = m[1]
	}
	if strings.Contains(text, "NOAUTH") {
		obs.Extra = strings.TrimSpace(obs.Extra + " auth-required")
	}
	return obs, nil
}

func init() { Register(redisProber{}) }

// memcachedProber asks for the server version.
type memcachedProber struct{}

func (memcachedProber) Name() string   { return "memcached" }
func (memcachedProber) Greeting() bool { return false }

func (memcachedProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write([]byte("version\r\n")); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	raw, err := readUntil(rec, 512, hasLine)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	text := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(text, "VERSION") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "memcached", Product: "memcached", Raw: raw, Banner: text}
	fields := strings.Fields(text)
	if len(fields) > 1 {
		obs.Version = fields[1]
	}
	return obs, nil
}

func init() { Register(memcachedProber{}) }

// mongoProber sends an OP_MSG hello command.
type mongoProber struct{}

func (mongoProber) Name() string   { return "mongodb" }
func (mongoProber) Greeting() bool { return false }

func (mongoProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write(mongoHello()); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	raw, err := readUntil(rec, 8192, nil)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	text := string(raw)
	if !strings.Contains(text, "maxWireVersion") && !strings.Contains(text, "ismaster") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "mongodb", Product: "mongodb", Raw: raw}
	if m := regexp.MustCompile(`"version"\s*:\s*"([0-9][0-9A-Za-z.\-]*)"`).FindStringSubmatch(text); m != nil {
		obs.Version = m[1]
	}
	if m := regexp.MustCompile(`"maxWireVersion"\s*:\s*([0-9]+)`).FindStringSubmatch(text); m != nil {
		obs.Extra = "wire " + m[1]
	}
	return obs, nil
}

// mongoHello builds an OP_MSG hello command with a minimal BSON document.
func mongoHello() []byte {
	doc := bsonDocument(
		bsonInt32("hello", 1),
		bsonString("$db", "admin"),
	)
	body := make([]byte, 0, 16+4+1+len(doc))
	body = binary.BigEndian.AppendUint32(body, 0) // message length placeholder
	body = binary.BigEndian.AppendUint32(body, 1) // request id
	body = binary.BigEndian.AppendUint32(body, 0) // response to
	body = binary.BigEndian.AppendUint32(body, 2013)
	body = binary.BigEndian.AppendUint32(body, 0) // flag bits
	body = append(body, 0)                        // section kind 0
	body = append(body, doc...)
	binary.BigEndian.PutUint32(body[0:4], uint32(len(body)))
	return body
}

func bsonInt32(name string, value int32) []byte {
	out := []byte{0x10}
	out = append(out, name...)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(value))
	return out
}

func bsonString(name, value string) []byte {
	out := []byte{0x02}
	out = append(out, name...)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(len(value)+1))
	out = append(out, value...)
	out = append(out, 0)
	return out
}

func bsonDocument(elements ...[]byte) []byte {
	body := []byte{}
	for _, e := range elements {
		body = append(body, e...)
	}
	body = append(body, 0)
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	return append(out, body...)
}

func init() { Register(mongoProber{}) }

// jsonAPIProber issues an HTTP GET against a known API path and extracts
// version information from a JSON body.
type jsonAPIProber struct {
	name    string
	path    string
	version string
	// match is a regular expression applied to the body whose first capture
	// group is the version.
	match *regexp.Regexp
}

func (p *jsonAPIProber) Name() string   { return p.name }
func (p *jsonAPIProber) Greeting() bool { return false }

func (p *jsonAPIProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	host := o.HostHeader
	if host == "" {
		host = ap.Addr().Unmap().String()
	}
	ua := o.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}

	resp, body, err := httpGet(rec, host, p.path, ua, o.Timeout)
	if err != nil {
		return nil, err
	}
	obs := &Observation{
		Service: p.name,
		Raw:     rec.ReadBytes(),
		HTTP:    httpInfoFrom(resp, body, p.path),
	}
	if p.match != nil {
		if m := p.match.FindStringSubmatch(string(body)); m != nil && len(m) > 1 {
			obs.Version = m[1]
		}
	}
	obs.Product = p.name
	return obs, nil
}

func init() {
	Register(&jsonAPIProber{
		name:  "elasticsearch",
		path:  "/",
		match: regexp.MustCompile(`"number"\s*:\s*"([0-9][0-9A-Za-z.\-]*)"`),
	})
	Register(&jsonAPIProber{
		name:  "docker",
		path:  "/version",
		match: regexp.MustCompile(`"Version"\s*:\s*"([0-9][0-9A-Za-z.\-]*)"`),
	})
}

// httpInfoFrom converts an HTTP response into the shared HTTPInfo struct.
func httpInfoFrom(resp *http.Response, body []byte, path string) *HTTPInfo {
	info := &HTTPInfo{
		Status:      resp.StatusCode,
		StatusText:  strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))),
		HTTPVersion: resp.Proto,
		Server:      resp.Header.Get("Server"),
		ContentType: resp.Header.Get("Content-Type"),
		Redirect:    resp.Header.Get("Location"),
		Headers:     map[string]string{},
		BodyBytes:   len(body),
		Method:      "GET",
		Path:        path,
	}
	for k, v := range resp.Header {
		if len(v) > 0 {
			info.Headers[k] = v[0]
		}
	}
	return info
}

// decodeJSON is a small helper used by the API probers.
func decodeJSON(data []byte, v any) error { return json.Unmarshal(data, v) }

// bufioReader is retained for probers that need line oriented reads.
func bufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }
