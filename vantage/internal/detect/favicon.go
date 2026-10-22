package detect

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxFaviconSize bounds how much of a favicon is read.
const maxFaviconSize = 256 * 1024

// fetchFavicon retrieves /favicon.ico from an HTTP service and returns its
// fingerprint. It returns an empty string when the favicon is unavailable.
func fetchFavicon(conn net.Conn, host, ua string, timeout time.Duration) string {
	req := "GET /favicon.ico HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Accept: image/*\r\n" +
		"Connection: close\r\n\r\n"

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, req); err != nil {
		return ""
	}
	_ = conn.SetWriteDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFaviconSize))
	if err != nil && len(body) == 0 {
		return ""
	}
	if len(body) == 0 {
		return ""
	}
	return FaviconHash(body)
}

// looksLikeFavicon performs a cheap sanity check on the response body.
func looksLikeFavicon(body []byte) bool {
	return len(body) > 0 && !strings.Contains(string(body[:min(len(body), 64)]), "<html")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
