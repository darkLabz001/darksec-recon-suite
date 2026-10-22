package proto

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// This file holds the probers for the services that need a purpose built
// request rather than a textual greeting. Every probe is deliberately
// minimal: it asks a question that any implementation of the protocol
// answers, never sends credentials and never mutates remote state.

// dnsProber speaks DNS over TCP.
type dnsProber struct{}

func (dnsProber) Name() string   { return "dns" }
func (dnsProber) Greeting() bool { return false }

func (dnsProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)

	query := dnsVersionBindQuery()
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	_ = rec.SetWriteDeadline(time.Now().Add(o.Timeout))
	if _, err := rec.Write(frame); err != nil {
		return nil, err
	}
	_ = rec.SetWriteDeadline(time.Time{})
	_ = rec.SetReadDeadline(time.Now().Add(o.Timeout))

	var size [2]byte
	if _, err := io.ReadFull(rec, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 || n > 4096 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(rec, body); err != nil {
		return nil, err
	}
	if body[2]&0x80 == 0 {
		// The response bit is not set, so this is not a DNS answer.
		return nil, io.ErrUnexpectedEOF
	}

	obs := &Observation{Service: "dns", Product: "dns", Raw: body}
	if v := dnsTextAnswer(body); v != "" {
		obs.Version = v
		obs.Banner = v
	}
	return obs, nil
}

func init() { Register(dnsProber{}) }

// dnsVersionBindQuery builds a CHAOS class TXT query for "version.bind",
// which most resolvers answer with the version of their implementation.
func dnsVersionBindQuery() []byte {
	q := []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
	}
	q = append(q, dnsWireName("version.bind")...)
	q = append(q, 0x00, 0x10) // TYPE TXT
	q = append(q, 0x00, 0x03) // CLASS CH
	return q
}

// dnsWireName encodes a domain name in the DNS wire format.
func dnsWireName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0x00)
}

// dnsTextAnswer returns the first TXT answer of a DNS response.
func dnsTextAnswer(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])

	off := 12
	for i := 0; i < qd; i++ {
		next, ok := skipWireName(msg, off)
		if !ok {
			return ""
		}
		off = next + 4
	}
	for i := 0; i < an; i++ {
		next, ok := skipWireName(msg, off)
		if !ok {
			return ""
		}
		off = next
		if off+10 > len(msg) {
			return ""
		}
		rtype := int(msg[off])<<8 | int(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdlen > len(msg) {
			return ""
		}
		if rtype == 0x0010 { // TXT
			txt := msg[off : off+rdlen]
			for p := 0; p < len(txt); {
				l := int(txt[p])
				p++
				if p+l > len(txt) {
					break
				}
				if v := strings.TrimSpace(string(txt[p : p+l])); v != "" {
					return v
				}
				p += l
			}
		}
		off += rdlen
	}
	return ""
}

// skipWireName advances past a possibly compressed domain name.
func skipWireName(msg []byte, off int) (int, bool) {
	for {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0:
			return off + 2, true
		default:
			off += l + 1
		}
	}
}

// snmpProber asks for the system description over SNMP.
type snmpProber struct{}

func (snmpProber) Name() string   { return "snmp" }
func (snmpProber) Greeting() bool { return false }

func (snmpProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, snmpSysDescrRequest(), o.Timeout, 4096)
	if len(raw) < 2 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if raw[0] != 0x30 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "snmp", Product: "snmp", Raw: raw}
	if v := snmpText(raw); v != "" {
		obs.Version = v
		obs.Banner = v
	}
	return obs, nil
}

func init() { Register(snmpProber{}) }

// snmpSysDescrRequest builds an SNMPv1 GetRequest for sysDescr.0 using the
// public community, which is what makes a managed device answer.
func snmpSysDescrRequest() []byte {
	return []byte{
		0x30, 0x29, // SEQUENCE
		0x02, 0x01, 0x00, // INTEGER: version 1
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING: community
		0xa0, 0x1c, // GetRequest-PDU
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // INTEGER: request id
		0x02, 0x01, 0x00, // INTEGER: error status
		0x02, 0x01, 0x00, // INTEGER: error index
		0x30, 0x0e, // SEQUENCE: variable bindings
		0x30, 0x0c, // SEQUENCE: variable binding
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID sysDescr.0
		0x05, 0x00, // NULL
	}
}

// snmpText extracts the first printable string of an SNMP message.
func snmpText(raw []byte) string {
	for i := 0; i < len(raw)-1; i++ {
		if raw[i] != 0x04 {
			continue
		}
		l := int(raw[i+1])
		if l == 0 || i+2+l > len(raw) {
			continue
		}
		value := raw[i+2 : i+2+l]
		if printable(value) {
			return string(value)
		}
	}
	return ""
}

// printable reports whether a byte slice holds only printable text.
func printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// ajp13Prober sends an AJP13 forward request.
type ajp13Prober struct{}

func (ajp13Prober) Name() string   { return "ajp13" }
func (ajp13Prober) Greeting() bool { return false }

func (ajp13Prober) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, ajp13ForwardRequest(), o.Timeout, 2048)
	if len(raw) < 4 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// A container answers with its own magic bytes.
	if raw[0] != 0x41 || raw[1] != 0x42 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "ajp13", Product: "ajp13", Raw: raw}
	if idx := strings.Index(string(raw), "Servlet Engine"); idx >= 0 {
		rest := string(raw)[idx:]
		if end := strings.IndexAny(rest, "\x00\r\n"); end > 0 {
			rest = rest[:end]
		}
		obs.Product = "Apache Tomcat"
		obs.Extra = strings.TrimSpace(rest)
	}
	return obs, nil
}

func init() { Register(ajp13Prober{}) }

// ajp13ForwardRequest builds an AJP13 forward request for the root path.
func ajp13ForwardRequest() []byte {
	body := []byte{
		0x02, 0x02, // prefix code: forward request
		0x04,       // method: GET
		0x00,       // protocol: HTTP/0.9
		0x00, 0x03, // request uri: "/ "
		0x00, 0x00, // remote host
		0x00, 0x00, // remote port
		0x00, 0x00, // remote user
		0x00, 0x00, // reserved
		0x04,       // method: GET
		0x00, 0x00, // content type
		0x00, 0x00, // request headers
		0x00, // terminator
	}
	packet := []byte{0x12, 0x34, byte(len(body) >> 8), byte(len(body))}
	return append(packet, body...)
}

// socksProber negotiates a SOCKS handshake.
type socksProber struct{}

func (socksProber) Name() string   { return "socks" }
func (socksProber) Greeting() bool { return false }

func (socksProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)

	// SOCKS5 greeting with a single "no authentication" method.
	raw, err := exchange(rec, []byte{0x05, 0x01, 0x00}, o.Timeout, 64)
	if len(raw) >= 2 && raw[0] == 0x05 {
		if raw[1] != 0x00 {
			return nil, io.ErrUnexpectedEOF
		}
		obs := &Observation{Service: "socks", Product: "SOCKS5", Raw: raw}
		if raw[1] == 0xff {
			obs.Extra = "authentication required"
		}
		return obs, nil
	}

	// SOCKS4: the request and the answer share the same shape.
	raw, err = exchange(rec, []byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0, 0}, o.Timeout, 64)
	if len(raw) >= 2 && raw[0] == 0x00 {
		obs := &Observation{Service: "socks", Product: "SOCKS4", Raw: raw}
		if raw[1] != 0x5a {
			obs.Extra = "request rejected"
		}
		return obs, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, io.ErrUnexpectedEOF
}

func init() { Register(socksProber{}) }

// zookeeperProber asks the four letter word service for the state.
type zookeeperProber struct{}

func (zookeeperProber) Name() string   { return "zookeeper" }
func (zookeeperProber) Greeting() bool { return false }

func (zookeeperProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, []byte("ruok"), o.Timeout, 256)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	text := strings.TrimSpace(string(raw))
	if text != "imok" {
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "zookeeper", Product: "Apache ZooKeeper", Raw: raw, Banner: text}, nil
}

func init() { Register(zookeeperProber{}) }

// amqpProber sends the AMQP protocol header.
type amqpProber struct{}

func (amqpProber) Name() string   { return "amqp" }
func (amqpProber) Greeting() bool { return false }

func (amqpProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, []byte("AMQP\x00\x00\x09\x01"), o.Timeout, 256)
	if len(raw) < 8 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if !strings.HasPrefix(string(raw), "AMQP") {
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "amqp", Product: "AMQP", Raw: raw}, nil
}

func init() { Register(amqpProber{}) }

// mqttProber sends an MQTT connect packet.
type mqttProber struct{}

func (mqttProber) Name() string   { return "mqtt" }
func (mqttProber) Greeting() bool { return false }

func (mqttProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, mqttConnect(), o.Timeout, 256)
	if len(raw) < 4 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// The broker answers with a CONNACK packet.
	if raw[0] != 0x20 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "mqtt", Product: "MQTT", Raw: raw}
	if len(raw) >= 4 && raw[3] != 0x00 {
		obs.Extra = "connection refused"
	}
	return obs, nil
}

func init() { Register(mqttProber{}) }

// mqttConnect builds an MQTT 3.1.1 connect packet.
func mqttConnect() []byte {
	var payload []byte
	payload = append(payload, 0x00, 0x04, 'M', 'Q', 'T', 'T') // protocol name
	payload = append(payload, 0x04)                           // protocol level
	payload = append(payload, 0x02)                           // clean session
	payload = append(payload, 0x00, 0x3c)                     // keep alive
	clientID := "vantage"
	payload = append(payload, byte(len(clientID)>>8), byte(len(clientID)))
	payload = append(payload, clientID...)

	packet := []byte{0x10, byte(len(payload))}
	return append(packet, payload...)
}

// kafkaProber asks for the list of supported API versions.
type kafkaProber struct{}

func (kafkaProber) Name() string   { return "kafka" }
func (kafkaProber) Greeting() bool { return false }

func (kafkaProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, kafkaApiVersionsRequest(), o.Timeout, 1024)
	if len(raw) < 8 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// The response repeats the correlation id of the request.
	if binary.BigEndian.Uint32(raw[4:8]) != 1 {
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "kafka", Product: "Apache Kafka", Raw: raw}, nil
}

func init() { Register(kafkaProber{}) }

// kafkaApiVersionsRequest builds a Kafka ApiVersions request.
func kafkaApiVersionsRequest() []byte {
	body := []byte{
		0x00, 0x12, // api key: ApiVersions
		0x00, 0x00, // api version
		0x00, 0x00, 0x00, 0x01, // correlation id
		0x00, 0x07, 'v', 'a', 'n', 't', 'a', 'g', 'e', // client id
	}
	packet := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(body)))
	copy(packet[4:], body)
	return packet
}

// cassandraProber starts a CQL session.
type cassandraProber struct{}

func (cassandraProber) Name() string   { return "cassandra" }
func (cassandraProber) Greeting() bool { return false }

func (cassandraProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, cassandraStartup(), o.Timeout, 1024)
	if len(raw) < 9 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// The header holds the protocol version and the opcode of the answer.
	if raw[0]&0x7f > 0x05 {
		return nil, io.ErrUnexpectedEOF
	}
	opcode := raw[7]
	if opcode != 0x02 && opcode != 0x06 {
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "cassandra", Product: "Apache Cassandra", Raw: raw}, nil
}

func init() { Register(cassandraProber{}) }

// cassandraStartup builds a CQL native protocol STARTUP frame.
func cassandraStartup() []byte {
	body := []byte{0x00, 0x0a} // string length: "CQL_VERSION"
	body = append(body, "CQL_VERSION"...)
	body = append(body, 0x00, 0x05) // string length: "3.0.0"
	body = append(body, "3.0.0"...)

	frame := []byte{
		0x04,       // protocol version 4
		0x00,       // flags
		0x00, 0x00, // stream id
		0x05, // opcode: STARTUP
	}
	frame = append(frame, 0x00, 0x00, 0x00, byte(len(body)))
	return append(frame, body...)
}

// openvpnProber resets the session and waits for the server answer.
type openvpnProber struct{}

func (openvpnProber) Name() string   { return "openvpn" }
func (openvpnProber) Greeting() bool { return false }

func (openvpnProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	// P_CONTROL_HARD_RESET_CLIENT_V2 with an empty payload.
	packet := []byte{0x07, 0x00, 0x00, 0x00}
	raw, err := exchange(rec, packet, o.Timeout, 512)
	if len(raw) < 1 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	opcode := raw[0] >> 3
	if opcode < 1 || opcode > 8 {
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "openvpn", Product: "OpenVPN", Raw: raw}, nil
}

func init() { Register(openvpnProber{}) }

// bgpProber sends an OPEN message.
type bgpProber struct{}

func (bgpProber) Name() string   { return "bgp" }
func (bgpProber) Greeting() bool { return false }

func (bgpProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, bgpOpen(), o.Timeout, 1024)
	if len(raw) < 19 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// The marker is sixteen bytes of ones and the type is OPEN.
	for i := 0; i < 16; i++ {
		if raw[i] != 0xff {
			return nil, io.ErrUnexpectedEOF
		}
	}
	if raw[18] != 0x01 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "bgp", Product: "BGP", Raw: raw}
	if as := binary.BigEndian.Uint16(raw[19:21]); as != 0 && as != 23456 {
		obs.Extra = "as " + strconv.Itoa(int(as))
	}
	return obs, nil
}

func init() { Register(bgpProber{}) }

// bgpOpen builds a BGP OPEN message.
func bgpOpen() []byte {
	msg := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // marker
		0x00, 0x1d, // length
		0x01,       // type: OPEN
		0x04,       // version 4
		0x00, 0x00, // autonomous system number
		0x00, 0x3c, // hold time
		0x7f, 0x00, 0x00, 0x01, // identifier
		0x00, // optional parameter length
	}
	return msg
}

// rpcProber is the shared implementation of the RPC based services.
type rpcProber struct {
	name    string
	product string
	program uint32
	version uint32
	proc    uint32
}

func (p *rpcProber) Name() string   { return p.name }
func (p *rpcProber) Greeting() bool { return false }

func (p *rpcProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, rpcCall(p.program, p.version, p.proc), o.Timeout, 4096)
	if len(raw) < 8 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// Skip the record mark and read the message type.
	if raw[0]&0x80 != 0 {
		if len(raw) < 12 {
			return nil, io.ErrUnexpectedEOF
		}
		raw = raw[4:]
	}
	if binary.BigEndian.Uint32(raw[4:8]) != 1 { // REPLY
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: p.name, Product: p.product, Raw: raw}, nil
}

func init() {
	Register(&rpcProber{name: "nfs", product: "NFS", program: 100003, version: 3, proc: 0})
	Register(&rpcProber{name: "rpcbind", product: "rpcbind", program: 100000, version: 2, proc: 3})
	Register(&rpcProber{name: "msrpc", product: "Microsoft RPC", program: 100000, version: 3, proc: 0})
}

// rpcCall builds an RPC call with AUTH_NULL credentials.
func rpcCall(program, version, proc uint32) []byte {
	body := []byte{
		0x00, 0x00, 0x00, 0x01, // transaction id
		0x00, 0x00, 0x00, 0x00, // message type: CALL
		0x00, 0x00, 0x00, 0x02, // RPC version
	}
	body = binary.BigEndian.AppendUint32(body, program)
	body = binary.BigEndian.AppendUint32(body, version)
	body = binary.BigEndian.AppendUint32(body, proc)
	body = append(body, 0x00, 0x00, 0x00, 0x00) // credentials: AUTH_NULL
	body = append(body, 0x00, 0x00, 0x00, 0x00) // verifier: AUTH_NULL

	mark := make([]byte, 4)
	binary.BigEndian.PutUint32(mark, uint32(len(body))|0x80000000)
	return append(mark, body...)
}

// xmppProber opens an XML stream.
type xmppProber struct{}

func (xmppProber) Name() string   { return "xmpp" }
func (xmppProber) Greeting() bool { return false }

func (xmppProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	host := ap.Addr().Unmap().String()
	req := "<?xml version='1.0'?><stream:stream to='" + host +
		"' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
	raw, err := exchange(rec, []byte(req), o.Timeout, 1024)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	text := string(raw)
	if !strings.HasPrefix(strings.TrimSpace(text), "<?xml") && !strings.HasPrefix(strings.TrimSpace(text), "<stream:stream") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "xmpp", Product: "XMPP", Raw: raw}
	if idx := strings.Index(text, "from="); idx >= 0 {
		rest := text[idx+5:]
		if end := strings.IndexAny(rest, " '"); end > 0 {
			obs.Extra = "domain " + rest[:end]
		}
	}
	return obs, nil
}

func init() { Register(xmppProber{}) }

// syslogProber sends a syslog message and waits for the acknowledgement.
type syslogProber struct{}

func (syslogProber) Name() string   { return "syslog" }
func (syslogProber) Greeting() bool { return false }

func (syslogProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	msg := "<134>" + time.Now().UTC().Format(time.Stamp) + " vantage vantage: probe\r\n"
	raw, err := exchange(rec, []byte(msg), o.Timeout, 512)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "syslog", Product: "syslog", Raw: raw}, nil
}

func init() { Register(syslogProber{}) }

// ippProber issues an IPP operation against the print service.
type ippProber struct{}

func (ippProber) Name() string   { return "ipp" }
func (ippProber) Greeting() bool { return false }

func (ippProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	host := o.HostHeader
	if host == "" {
		host = ap.Addr().Unmap().String()
	}
	req := "POST /ipp/print HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/ipp\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	raw, err := exchange(rec, []byte(req), o.Timeout, 2048)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if !strings.HasPrefix(string(raw), "HTTP/") {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "ipp", Product: "IPP", Raw: raw}
	if m := regexpServerHeader(string(raw)); m != "" {
		obs.Extra = m
	}
	return obs, nil
}

func init() { Register(ippProber{}) }

// printerProber speaks PJL to a raw printing port.
type printerProber struct{}

func (printerProber) Name() string   { return "printer" }
func (printerProber) Greeting() bool { return false }

func (printerProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	req := "\x1b%-12345X@PJL ENTER LANGUAGE=POSTSCRIPT\r\n\x1b%-12345X@PJL EOJ\r\n"
	raw, err := exchange(rec, []byte(req), o.Timeout, 1024)
	if len(raw) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "printer", Product: "printer", Raw: raw}, nil
}

func init() { Register(printerProber{}) }

// netbiosProber asks for a NetBIOS session service.
type netbiosProber struct{}

func (netbiosProber) Name() string   { return "netbios" }
func (netbiosProber) Greeting() bool { return false }

func (netbiosProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, netbiosSessionRequest(), o.Timeout, 512)
	if len(raw) < 4 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// A session response is either positive or negative.
	if raw[0] != 0x81 && raw[0] != 0x82 {
		return nil, io.ErrUnexpectedEOF
	}
	return &Observation{Service: "netbios", Product: "NetBIOS", Raw: raw}, nil
}

func init() { Register(netbiosProber{}) }

// netbiosSessionRequest builds a NetBIOS session request for the wildcard
// name, which every file service answers.
func netbiosSessionRequest() []byte {
	name := make([]byte, 16)
	name[0] = '*'
	for i := 1; i < len(name); i++ {
		name[i] = ' '
	}
	encoded := make([]byte, 0, 34)
	encoded = append(encoded, byte(len(name)*2))
	for _, b := range name {
		encoded = append(encoded, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	encoded = append(encoded, 0x00) // scope

	body := []byte{0x00, 0x00, byte(len(encoded) >> 8), byte(len(encoded))}
	body = append(body, encoded...)
	return body
}

// oracleProber sends a TNS connect packet.
//
// The packet is deliberately minimal: a listener that does not understand
// it still answers with a TNS error packet, which identifies the service
// just as well as an accept would.
type oracleProber struct{}

func (oracleProber) Name() string   { return "oracle" }
func (oracleProber) Greeting() bool { return false }

func (oracleProber) Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error) {
	rec := newRecorder(c)
	raw, err := exchange(rec, tnsConnect(), o.Timeout, 1024)
	if len(raw) < 4 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	// The first byte of a TNS packet is its type and the second one is
	// always reserved.
	packetType := raw[0]
	if packetType < 1 || packetType > 12 || raw[1] != 0x00 {
		return nil, io.ErrUnexpectedEOF
	}
	obs := &Observation{Service: "oracle", Product: "Oracle TNS", Raw: raw}
	switch packetType {
	case 2:
		obs.Extra = "accept"
	case 5:
		obs.Extra = "refuse"
	case 6:
		obs.Extra = "error"
	}
	return obs, nil
}

func init() { Register(oracleProber{}) }

// tnsConnect builds a minimal TNS connect packet.
func tnsConnect() []byte {
	const headerLen = 42

	connectData := []byte{
		0x01, 0x00, // connect descriptor, length placeholder
		0x01, 0x00, // service options: empty
		0x02, 0x00, // session data: empty
		0x04, 0x07, 'v', 'a', 'n', 't', 'a', 'g', 'e', // connect data
	}
	connectData[1] = byte(len(connectData))

	packet := make([]byte, headerLen, headerLen+len(connectData))
	binary.BigEndian.PutUint16(packet[0:2], uint16(headerLen+len(connectData)))
	packet[2] = 0x01                                // CONNECT
	packet[3] = 0x00                                // reserved
	binary.BigEndian.PutUint16(packet[6:8], 0x0001) // version
	binary.BigEndian.PutUint16(packet[8:10], 0x0001)
	binary.BigEndian.PutUint32(packet[10:14], 0x00000001) // service options
	binary.BigEndian.PutUint16(packet[32:34], 0x7f08)     // value of 1 in hardware
	binary.BigEndian.PutUint16(packet[34:36], uint16(len(connectData)))
	binary.BigEndian.PutUint16(packet[36:38], uint16(headerLen))
	binary.BigEndian.PutUint16(packet[38:40], 0x4000) // max receive data

	return append(packet, connectData...)
}

// regexpServerHeader returns the value of the Server header of an HTTP
// response.
func regexpServerHeader(raw string) string {
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) < 8 {
			continue
		}
		if strings.EqualFold(line[:7], "Server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}
