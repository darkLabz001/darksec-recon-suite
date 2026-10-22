package proto

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// textProber covers the many services that identify themselves with a
// short textual greeting.
type textProber struct {
	name     string
	greeting bool
	// stop decides when the greeting is complete.
	stop func([]byte) bool
	// pattern extracts the interesting part of the greeting.
	pattern *regexp.Regexp
	// keywords maps a substring of the greeting to a canonical product.
	keywords []keyword
	// service overrides the canonical service name.
	service string
}

type keyword struct {
	match   string
	product string
}

func (p *textProber) Name() string { return p.name }

func (p *textProber) Greeting() bool { return p.greeting }

// Probe reads the greeting and extracts product and version information.
func (p *textProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	raw, err := readUntil(rec, 4096, p.stop)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}

	obs := &Observation{
		Service: p.service,
		Raw:     raw,
		Banner:  strings.TrimSpace(string(raw)),
	}
	if obs.Service == "" {
		obs.Service = p.name
	}

	text := string(raw)
	if p.pattern != nil {
		if m := p.pattern.FindStringSubmatch(text); m != nil {
			if len(m) > 1 && m[1] != "" {
				product, version := splitProductVersion(m[1])
				obs.Product = product
				obs.Version = version
			}
		}
	}
	if obs.Product == "" {
		for _, kw := range p.keywords {
			if strings.Contains(strings.ToLower(text), kw.match) {
				obs.Product = kw.product
				break
			}
		}
	}
	return obs, nil
}

// readUntil reads from c until the stop predicate is satisfied, the read
// deadline expires or max bytes have been read.
func readUntil(c net.Conn, max int, stop func([]byte) bool) ([]byte, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 1024)
	for len(buf) < max {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if stop != nil && stop(buf) {
				return buf, nil
			}
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

// hasLine reports whether b contains a complete line.
func hasLine(b []byte) bool { return bytes.Contains(b, []byte("\n")) }

// splitProductVersion splits a token such as "OpenSSH_9.2p1" into a
// product name and a version. The version starts at the first digit.
func splitProductVersion(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			product := strings.Trim(s[:i], "_- ./")
			rest := s[i:]
			// The version is the leading run of version characters.
			j := 0
			for j < len(rest) && isVersionChar(rest[j]) {
				j++
			}
			return product, rest[:j]
		}
	}
	return strings.Trim(s, "_- ./"), ""
}

// isVersionChar reports whether a byte can appear in a version string.
func isVersionChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c == '.' || c == '-' || c == '_':
		return true
	}
	return false
}

var (
	sshPattern  = regexp.MustCompile(`SSH-[0-9.]+-([^\s\r\n]+)`)
	ftpPattern  = regexp.MustCompile(`(?s)^\d{3}[- ]([^\r\n)]*)`)
	smtpPattern = regexp.MustCompile(`(?s)^\d{3}[- ]([^\r\n]*)`)
	pop3Pattern = regexp.MustCompile(`(?s)^\+OK[ -]?([^\r\n]*)`)
	imapPattern = regexp.MustCompile(`(?s)^\*\s+(?:OK|PREAUTH)[ -]?(?:\[([^\]]*)\][ -]?)?([^\r\n]*)`)
	vncPattern  = regexp.MustCompile(`RFB (\d{3})\.(\d{3})`)
	ircPattern  = regexp.MustCompile(`(?s)^:[^\s]+ ([0-9]{3}) ([^\r\n]*)`)
	ntpPattern  = regexp.MustCompile(`\x1c`)
	rtspPattern = regexp.MustCompile(`(?s)^RTSP/1\.0 (\d{3})`)
	sipPattern  = regexp.MustCompile(`(?s)^SIP/2\.0 (\d{3})`)
)

func init() {
	Register(&textProber{
		name:     "ssh",
		greeting: true,
		stop:     hasLine,
		pattern:  sshPattern,
	})
	Register(&textProber{
		name:     "ftp",
		greeting: true,
		stop:     hasLine,
		pattern:  ftpPattern,
		keywords: []keyword{{"proftpd", "ProFTPD"}, {"vsftpd", "vsftpd"}, {"filezilla", "FileZilla"}, {"pure-ftpd", "Pure-FTPd"}, {"pureftpd", "Pure-FTPd"}, {"serv-u", "Serv-U"}, {"gftpd", "gFTPD"}},
	})
	Register(&textProber{
		name:     "smtp",
		greeting: true,
		stop:     hasLine,
		pattern:  smtpPattern,
		keywords: []keyword{{"postfix", "Postfix"}, {"exim", "Exim"}, {"sendmail", "Sendmail"}, {"exchange", "Microsoft Exchange"}, {"dovecot", "Dovecot"}, {"courier", "Courier"}, {"zimbra", "Zimbra"}, {"qmail", "qmail"}, {"mailcow", "Mailcow"}},
	})
	Register(&textProber{
		name:     "pop3",
		greeting: true,
		stop:     hasLine,
		pattern:  pop3Pattern,
		keywords: []keyword{{"dovecot", "Dovecot"}, {"courier", "Courier"}, {"gpop3", "gpop3"}, {"solid", "solid"}},
	})
	Register(&textProber{
		name:     "imap",
		greeting: true,
		stop:     hasLine,
		pattern:  imapPattern,
		keywords: []keyword{{"dovecot", "Dovecot"}, {"courier", "Courier"}, {"zimbra", "Zimbra"}, {"gimap", "Cyrus"}},
	})
	Register(&textProber{
		name:     "vnc",
		greeting: true,
		stop:     hasLine,
		pattern:  vncPattern,
		service:  "vnc",
	})
	Register(&textProber{
		name:     "irc",
		greeting: false,
		stop:     hasLine,
		pattern:  ircPattern,
		keywords: []keyword{{"inspircd", "InspIRCd"}, {"charybdis", "Charybdis"}, {"unrealircd", "UnrealIRCd"}, {"hexchat", "HexChat"}},
	})
	Register(&textProber{
		name:     "rtsp",
		greeting: false,
		stop:     hasLine,
		pattern:  rtspPattern,
	})
	Register(&textProber{
		name:     "sip",
		greeting: false,
		stop:     hasLine,
		pattern:  sipPattern,
	})
	Register(&textProber{
		name:     "telnet",
		greeting: true,
		stop:     hasLine,
	})
	Register(&textProber{
		name:     "ntp",
		greeting: false,
		stop:     hasLine,
		pattern:  ntpPattern,
	})
}

// ircProber speaks enough IRC to trigger the server's welcome burst.
type ircProber struct{}

func (ircProber) Name() string   { return "irc" }
func (ircProber) Greeting() bool { return false }

func (ircProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	_, err := io.WriteString(rec, "NICK vantage\r\nUSER vantage 0 * :vantage\r\n")
	if err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	raw, err := readUntil(rec, 4096, hasLine)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "irc", Raw: raw, Banner: strings.TrimSpace(string(raw))}
	if m := ircPattern.FindStringSubmatch(string(raw)); m != nil {
		obs.Extra = strings.TrimSpace(m[2])
	}
	for _, kw := range []keyword{{"inspircd", "InspIRCd"}, {"charybdis", "Charybdis"}, {"unrealircd", "UnrealIRCd"}} {
		if strings.Contains(strings.ToLower(string(raw)), kw.match) {
			obs.Product = kw.product
			break
		}
	}
	return obs, nil
}

// init registers the dedicated IRC prober over the generic one.
func init() {
	Register(ircProber{})
}

// ntpProber issues a minimal SNTP request.
type ntpProber struct{}

func (ntpProber) Name() string   { return "ntp" }
func (ntpProber) Greeting() bool { return false }

func (ntpProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	req := make([]byte, 48)
	req[0] = 0x1b // LI 0, VN 3, Mode 3 (client)
	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write(req); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	buf := make([]byte, 48)
	n, err := rec.Read(buf)
	if n == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	mode := buf[0] & 0x07
	if mode != 4 {
		return nil, io.ErrUnexpectedEOF
	}
	version := (buf[0] >> 3) & 0x07
	stratum := int(buf[1])
	return &Observation{
		Service: "ntp",
		Product: "ntp",
		Version: strconv.Itoa(int(version)),
		Extra:   "stratum " + strconv.Itoa(stratum),
		Raw:     buf[:n],
	}, nil
}

func init() {
	Register(ntpProber{})
}
