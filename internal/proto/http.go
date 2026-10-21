package proto

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// HTTPInfo describes the observable characteristics of an HTTP service.
type HTTPInfo struct {
	// Status is the HTTP status code of the response.
	Status int
	// StatusText is the reason phrase.
	StatusText string
	// HTTPVersion is the protocol version, for example "HTTP/1.1".
	HTTPVersion string
	// Title is the contents of the HTML title element, if present.
	Title string
	// Server is the value of the Server header.
	Server string
	// ContentType is the value of the Content-Type header.
	ContentType string
	// Redirect is the value of the Location header.
	Redirect string
	// Headers holds the response headers with canonical names.
	Headers map[string]string
	// BodyBytes is the number of body bytes read.
	BodyBytes int
	// Method is the HTTP method used for the probe.
	Method string
	// Path is the request path used for the probe.
	Path string
}

type httpProber struct {
	useTLS bool
}

func init() {
	Register(&httpProber{})
	Register(&httpProber{useTLS: true})
}

// Name returns the canonical service name.
func (p *httpProber) Name() string {
	if p.useTLS {
		return "https"
	}
	return "http"
}

// Greeting reports that HTTP servers wait for the client to speak.
func (p *httpProber) Greeting() bool { return false }

// Probe performs an HTTP request and parses the response.
func (p *httpProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	conn := net.Conn(rec)

	var obs *Observation
	if p.useTLS {
		tlsConn, info, ja3, ja3s, err := clientTLS(ctx, conn, ap, o)
		if err != nil {
			return nil, err
		}
		obs = &Observation{Service: "https", TLS: info, JA3: ja3, JA3S: ja3s}
		conn = tlsConn
	} else {
		obs = &Observation{Service: "http"}
	}

	host := o.HostHeader
	if host == "" {
		host = ap.Addr().Unmap().String()
	}
	ua := o.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}

	resp, body, err := httpGet(conn, host, "/", ua, o.Timeout)
	if err != nil {
		return nil, err
	}

	info := httpInfoFrom(resp, body, "/")
	info.Title = extractTitle(body)

	obs.HTTP = info
	obs.Raw = rec.ReadBytes()
	obs.Banner = strings.TrimSpace(string(obs.Raw))

	// The Server header is a useful product hint even when the fingerprint
	// rules do not recognise it.
	if info.Server != "" {
		obs.Product = info.Server
	}
	if info.Title != "" {
		obs.Extra = info.Title
	}
	return obs, nil
}

// httpGet issues a GET request over an established connection and returns
// the parsed response together with the body.
func httpGet(c net.Conn, host, path, ua string, timeout time.Duration) (*http.Response, []byte, error) {
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Accept: */*\r\n" +
		"Accept-Encoding: identity\r\n" +
		"Connection: close\r\n\r\n"

	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(c, req); err != nil {
		return nil, nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	_ = c.SetReadDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp, body, nil
}

// extractTitle pulls the contents of the first HTML title element.
func extractTitle(body []byte) string {
	const openTag = "<title"
	const closeTag = "</title>"

	lower := strings.ToLower(string(body))
	start := strings.Index(lower, openTag)
	if start < 0 {
		return ""
	}
	rest := lower[start:]
	end := strings.Index(rest, ">")
	if end < 0 {
		return ""
	}
	rest = rest[end+1:]
	stop := strings.Index(rest, closeTag)
	if stop < 0 {
		return ""
	}
	title := strings.TrimSpace(string(body[start+end+1 : start+end+1+stop]))
	title = strings.Join(strings.Fields(title), " ")
	return title
}

// httpStatusText strips the numeric code from a status line.
func httpStatusText(status string, code int) string {
	return strings.TrimSpace(strings.TrimPrefix(status, strconv.Itoa(code)))
}
