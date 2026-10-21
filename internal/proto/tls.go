package proto

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// TLSInfo describes the observable characteristics of a TLS service.
type TLSInfo struct {
	// Version is the negotiated protocol version, for example "TLS 1.3".
	Version string
	// CipherSuite is the negotiated cipher suite.
	CipherSuite string
	// ALPN is the negotiated application protocol.
	ALPN string
	// Subject is the certificate subject distinguished name.
	Subject string
	// Issuer is the certificate issuer distinguished name.
	Issuer string
	// Serial is the certificate serial number in hexadecimal.
	Serial string
	// NotBefore is the start of the validity period.
	NotBefore string
	// NotAfter is the end of the validity period.
	NotAfter string
	// Expired reports whether the certificate is outside its validity window.
	Expired bool
	// SelfSigned reports whether the certificate is self signed.
	SelfSigned bool
	// SANs lists the subject alternative names.
	SANs []string
	// KeyType describes the public key algorithm.
	KeyType string
	// SigAlg describes the certificate signature algorithm.
	SigAlg string
}

// clientTLS completes a TLS handshake over the supplied connection and
// returns the negotiated parameters together with the handshake
// fingerprints.
//
// The handshake is performed without certificate verification: a port
// scanner must be able to inspect services that present invalid, expired
// or self signed certificates.
func clientTLS(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (net.Conn, *TLSInfo, string, string, error) {
	rec := newRecorder(c)

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	if o.HostHeader != "" {
		cfg.ServerName = strings.Split(o.HostHeader, ":")[0]
	} else if !ap.Addr().IsLoopback() {
		// Setting ServerName to an IP literal disables SNI, which many
		// servers require, so only use it for real host names.
		cfg.ServerName = ""
	}

	tlsConn := tls.Client(rec, cfg)
	deadline := time.Now().Add(o.Timeout)
	_ = tlsConn.SetDeadline(deadline)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, "", "", err
	}
	_ = tlsConn.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	info := describeState(state)

	var ja3, ja3s string
	if o.EnableJA3 {
		raw := rec.ReadBytes()
		written := rec.WrittenBytes()
		ja3 = ja3FromClientHello(written)
		ja3s = ja3sFromServerHello(raw)
	}
	return tlsConn, info, ja3, ja3s, nil
}

func describeState(state tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.NegotiatedProtocol) > 0 {
		info.ALPN = state.NegotiatedProtocol
	}
	if len(state.PeerCertificates) == 0 {
		return info
	}

	leaf := state.PeerCertificates[0]
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	info.Serial = strings.ToLower(leaf.SerialNumber.String())
	info.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	info.Expired = time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore)
	info.SANs = leaf.DNSNames
	if len(leaf.DNSNames) == 0 {
		info.SANs = nil
	}
	info.KeyType = keyTypeName(leaf.PublicKeyAlgorithm)
	info.SigAlg = leaf.SignatureAlgorithm.String()

	if len(state.PeerCertificates) > 1 {
		// A chain was presented; treat it as non self signed.
		info.SelfSigned = false
	} else {
		info.SelfSigned = leaf.Issuer.String() == leaf.Subject.String()
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func keyTypeName(algo x509.PublicKeyAlgorithm) string {
	switch algo {
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return algo.String()
	}
}

// ja3FromClientHello computes the JA3 fingerprint of a recorded
// ClientHello message.
//
// The fingerprint is the MD5 of
//
//	SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
func ja3FromClientHello(raw []byte) string {
	msg, ok := firstHandshake(raw, 1 /* clientHello */)
	if !ok {
		return ""
	}

	version := ""
	var ciphers []string
	var extensions []int
	var curves []int
	var formats []int

	pos := 0
	if len(msg) < 2 {
		return ""
	}
	version = fmt.Sprintf("%d", uint16(msg[0])<<8|uint16(msg[1]))
	pos = 2
	if len(msg) < pos+32 {
		return ""
	}
	pos += 32 // random

	if len(msg) < pos+1 {
		return ""
	}
	sidLen := int(msg[pos])
	pos++
	if len(msg) < pos+sidLen {
		return ""
	}
	pos += sidLen

	if len(msg) < pos+2 {
		return ""
	}
	csLen := int(uint16(msg[pos])<<8 | uint16(msg[pos+1]))
	pos += 2
	if len(msg) < pos+csLen {
		return ""
	}
	for i := 0; i+1 < csLen; i += 2 {
		ci := int(uint16(msg[pos+i])<<8 | uint16(msg[pos+i+1]))
		if isGREASE(ci) {
			continue
		}
		ciphers = append(ciphers, strconv.Itoa(ci))
	}
	pos += csLen

	if len(msg) < pos+1 {
		return ""
	}
	compLen := int(msg[pos])
	pos++
	if len(msg) < pos+compLen {
		return ""
	}
	pos += compLen

	if len(msg) < pos+2 {
		return ""
	}
	extLen := int(uint16(msg[pos])<<8 | uint16(msg[pos+1]))
	pos += 2
	if len(msg) < pos+extLen {
		return ""
	}
	end := pos + extLen
	for pos+4 <= end {
		extType := int(uint16(msg[pos])<<8 | uint16(msg[pos+1]))
		extDataLen := int(uint16(msg[pos+2])<<8 | uint16(msg[pos+3]))
		pos += 4
		if pos+extDataLen > end {
			break
		}
		data := msg[pos : pos+extDataLen]
		if !isGREASE(extType) {
			extensions = append(extensions, extType)
		}
		switch extType {
		case 10: // supported_groups
			if len(data) >= 2 {
				n := int(uint16(data[0])<<8 | uint16(data[1]))
				for i := 0; i+1 < n && 2+i+1 < len(data); i += 2 {
					curves = append(curves, int(uint16(data[2+i])<<8|uint16(data[2+i+1])))
				}
			}
		case 11: // ec_point_formats
			if len(data) >= 1 {
				n := int(data[0])
				for i := 0; i < n && 1+i < len(data); i++ {
					formats = append(formats, int(data[1+i]))
				}
			}
		}
		pos += extDataLen
	}

	joined := strings.Join(ciphers, "-")
	joinedExt := make([]string, 0, len(extensions))
	for _, e := range extensions {
		joinedExt = append(joinedExt, strconv.Itoa(e))
	}
	joinedCurves := make([]string, 0, len(curves))
	for _, c := range curves {
		joinedCurves = append(joinedCurves, strconv.Itoa(c))
	}
	joinedFormats := make([]string, 0, len(formats))
	for _, f := range formats {
		joinedFormats = append(joinedFormats, strconv.Itoa(f))
	}

	plain := fmt.Sprintf("%s,%s,%s,%s,%s", version, joined, strings.Join(joinedExt, "-"), strings.Join(joinedCurves, "-"), strings.Join(joinedFormats, "-"))
	return md5Hex(plain)
}

// ja3sFromServerHello computes the JA3S fingerprint of a recorded
// ServerHello message.
//
// The fingerprint is the MD5 of
//
//	SSLVersion,Cipher,Extensions
func ja3sFromServerHello(raw []byte) string {
	msg, ok := firstHandshake(raw, 2 /* serverHello */)
	if !ok {
		return ""
	}
	pos := 0
	if len(msg) < 2 {
		return ""
	}
	version := fmt.Sprintf("%d", uint16(msg[0])<<8|uint16(msg[1]))
	pos = 2
	if len(msg) < pos+32 {
		return ""
	}
	pos += 32
	if len(msg) < pos+1 {
		return ""
	}
	sidLen := int(msg[pos])
	pos++
	if len(msg) < pos+sidLen {
		return ""
	}
	pos += sidLen
	if len(msg) < pos+3 {
		return ""
	}
	cipher := strconv.Itoa(int(uint16(msg[pos])<<8 | uint16(msg[pos+1])))
	pos += 2
	pos++ // compression method
	if len(msg) < pos+2 {
		return ""
	}
	extLen := int(uint16(msg[pos])<<8 | uint16(msg[pos+1]))
	pos += 2
	if len(msg) < pos+extLen {
		return ""
	}
	end := pos + extLen
	var extensions []string
	for pos+4 <= end {
		extType := int(uint16(msg[pos])<<8 | uint16(msg[pos+1]))
		extDataLen := int(uint16(msg[pos+2])<<8 | uint16(msg[pos+3]))
		pos += 4
		if pos+extDataLen > end {
			break
		}
		if !isGREASE(extType) {
			extensions = append(extensions, strconv.Itoa(extType))
		}
		pos += extDataLen
	}

	plain := fmt.Sprintf("%s,%s,%s", version, cipher, strings.Join(extensions, "-"))
	return md5Hex(plain)
}

// firstHandshake extracts the first handshake message of the given type
// from a recorded TLS stream.
func firstHandshake(raw []byte, want byte) ([]byte, bool) {
	pos := 0
	for pos+5 <= len(raw) {
		contentType := raw[pos]
		length := int(uint16(raw[pos+3])<<8 | uint16(raw[pos+4]))
		body := raw[pos+5 : pos+5+length]
		if pos+5+length > len(raw) {
			return nil, false
		}
		if contentType == 22 { // handshake
			hpos := 0
			for hpos+4 <= len(body) {
				msgType := body[hpos]
				msgLen := int(body[hpos+1])<<16 | int(body[hpos+2])<<8 | int(body[hpos+3])
				if hpos+4+msgLen > len(body) {
					return nil, false
				}
				if msgType == want {
					return body[hpos+4 : hpos+4+msgLen], true
				}
				hpos += 4 + msgLen
			}
		}
		pos += 5 + length
	}
	return nil, false
}

// isGREASE reports whether a value is one of the GREASE values that TLS
// implementations insert to keep middleboxes from caching a handshake.
//
// The GREASE values are 0x0a0a, 0x1a1a, 0x2a2a ... 0xfafa. The JA3
// specification removes them before hashing, because they change on every
// connection and would make the fingerprint useless.
func isGREASE(v int) bool {
	return v&0x0f0f == 0x0a0a && v&0xff == v>>8
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
