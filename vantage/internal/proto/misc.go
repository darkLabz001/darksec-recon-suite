package proto

import (
	"context"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// sipProber issues an OPTIONS request.
type sipProber struct{}

func (sipProber) Name() string   { return "sip" }
func (sipProber) Greeting() bool { return false }

func (sipProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	host := ap.Addr().Unmap().String()
	req := "OPTIONS sip:" + host + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + host + ":5060;branch=z9hG4bK-vantage-1\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: <sip:" + host + ">\r\n" +
		"From: <sip:vantage@" + host + ">;tag=vantage\r\n" +
		"Call-ID: vantage@" + host + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Contact: <sip:vantage@" + host + ">\r\n" +
		"Content-Length: 0\r\n\r\n"

	raw, err := exchange(rec, []byte(req), o.Timeout, 4096)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if !strings.HasPrefix(string(raw), "SIP/") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "sip", Product: "sip", Raw: raw, Banner: strings.TrimSpace(string(raw))}
	if m := regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`).FindStringSubmatch(string(raw)); m != nil {
		obs.Product = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`SIP/2\.0 (\d{3})`).FindStringSubmatch(string(raw)); m != nil {
		obs.Extra = "status " + m[1]
	}
	return obs, nil
}

func init() { Register(sipProber{}) }

// rtspProber issues an OPTIONS request.
type rtspProber struct{}

func (rtspProber) Name() string   { return "rtsp" }
func (rtspProber) Greeting() bool { return false }

func (rtspProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	host := ap.Addr().Unmap().String()
	req := "OPTIONS rtsp://" + host + "/ RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"User-Agent: " + DefaultUserAgent + "\r\n\r\n"

	raw, err := exchange(rec, []byte(req), o.Timeout, 4096)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if !strings.HasPrefix(string(raw), "RTSP/") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "rtsp", Product: "rtsp", Raw: raw, Banner: strings.TrimSpace(string(raw))}
	if m := regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`).FindStringSubmatch(string(raw)); m != nil {
		obs.Product = strings.TrimSpace(m[1])
	}
	return obs, nil
}

func init() { Register(rtspProber{}) }

// rdpProber sends a TPKT/X.224 connection request.
type rdpProber struct{}

func (rdpProber) Name() string   { return "rdp" }
func (rdpProber) Greeting() bool { return false }

func (rdpProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	payload := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT header
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 connection request
		0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, // RDP negotiation request
	}
	raw, err := exchange(rec, payload, o.Timeout, 1024)
	if len(raw) < 4 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if raw[0] != 0x03 || raw[1] != 0x00 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "rdp", Product: "rdp", Raw: raw}
	if m := regexp.MustCompile(`Cookie:.*?msts=([^\r\n;]+)`).FindStringSubmatch(string(raw)); m != nil {
		obs.Extra = strings.TrimSpace(m[1])
	}
	return obs, nil
}

func init() { Register(rdpProber{}) }

// smbProber sends a NetBIOS session request with an SMB1 negotiate.
type smbProber struct{}

func (smbProber) Name() string   { return "smb" }
func (smbProber) Greeting() bool { return false }

func (smbProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	payload := smbNegotiate()
	raw, err := exchange(rec, payload, o.Timeout, 2048)
	if len(raw) < 5 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if !strings.Contains(string(raw), "SMB") && !strings.Contains(string(raw), "\xffSMB") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "smb", Product: "smb", Raw: raw}
	return obs, nil
}

// smbNegotiate builds a NetBIOS session service header followed by an SMB1
// negotiate request.
func smbNegotiate() []byte {
	smb := []byte{
		0xff, 0x53, 0x4d, 0x42, // SMB magic
		0x72,                   // command: negotiate
		0x00, 0x00, 0x00, 0x18, // flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	out := []byte{0x00, 0x00, 0x00, byte(len(smb))}
	out = append(out, smb...)
	return out
}

func init() { Register(smbProber{}) }

// ldapProber sends a search request for the root DSE.
type ldapProber struct{}

func (ldapProber) Name() string   { return "ldap" }
func (ldapProber) Greeting() bool { return false }

func (ldapProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	payload := []byte{
		0x30, 0x0d, // LDAPMessage SEQUENCE
		0x02, 0x01, 0x01, // messageID 1
		0x60, 0x08, // searchRequest [APPLICATION 3]
		0x04, 0x00, // baseObject ""
		0x0a, 0x00, // scope baseObject
		0x0a, 0x00, // derefAliases neverDerefAliases
		0xa0, 0x00, // filter and[]
	}
	raw, err := exchange(rec, payload, o.Timeout, 4096)
	if len(raw) < 2 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if raw[0] != 0x30 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "ldap", Product: "ldap", Raw: raw}
	if m := regexp.MustCompile(`(?i)(OpenLDAP|Microsoft|389 Directory|Apache|NetIQ|SunOne|Oracle|Ericsson|IBM)`).FindString(string(raw)); m != "" {
		obs.Product = m
	}
	return obs, nil
}

func init() { Register(ldapProber{}) }

// mssqlProber sends a TDS prelogin packet.
type mssqlProber struct{}

func (mssqlProber) Name() string   { return "mssql" }
func (mssqlProber) Greeting() bool { return false }

func (mssqlProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, mssqlPrelogin(), o.Timeout, 1024)
	if len(raw) < 8 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if raw[0] != 0x04 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "mssql", Product: "mssql", Raw: raw}
	if m := regexp.MustCompile(`(?i)(Microsoft SQL Server)[^\r\n\x00]*`).FindString(string(raw)); m != "" {
		obs.Product = "Microsoft SQL Server"
		if v := regexp.MustCompile(`(\d{1,2}\.\d{1,2}\.\d{1,4}(?:\.\d{1,4})?)`).FindString(m); v != "" {
			obs.Version = v
		}
	}
	return obs, nil
}

// mssqlPrelogin builds a TDS prelogin packet.
func mssqlPrelogin() []byte {
	body := []byte{
		0x00, 0x00, 0x00, 0x06, 0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00, // version 15.0.2000.5
		0x01, 0x06, 0x00, 0x01, 0x00, // encryption: not required
		0x02, 0x07, 0x00, 0x00, // instance name
		0xff, // terminator
	}
	header := []byte{0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	total := len(header) + len(body)
	header[2] = byte(total >> 8)
	header[3] = byte(total)
	return append(header, body...)
}

func init() { Register(mssqlProber{}) }

// tlsTextProber wraps a textual prober in a TLS handshake. It backs the
// imaps, pop3s, smtps and ldaps services.
type tlsTextProber struct {
	name string
	base string
}

func (p *tlsTextProber) Name() string   { return p.name }
func (p *tlsTextProber) Greeting() bool { return true }

func (p *tlsTextProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	tlsConn, info, ja3, ja3s, err := clientTLS(ctx, c, ap, o)
	if err != nil {
		return nil, err
	}
	base, ok := Lookup(p.base)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	obs, err := base.Probe(ctx, tlsConn, ap, o)
	if err != nil {
		return nil, err
	}
	obs.Service = p.name
	obs.TLS = info
	obs.JA3 = ja3
	obs.JA3S = ja3s
	return obs, nil
}

func init() {
	Register(&tlsTextProber{name: "imaps", base: "imap"})
	Register(&tlsTextProber{name: "pop3s", base: "pop3"})
	Register(&tlsTextProber{name: "smtps", base: "smtp"})
	Register(&tlsTextProber{name: "ldaps", base: "ldap"})
}
