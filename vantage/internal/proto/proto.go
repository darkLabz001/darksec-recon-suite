// Package proto implements protocol specific probes used for service
// detection.
//
// Every prober speaks the wire protocol of a service far enough to make the
// service identify itself: reading a greeting, exchanging a minimal request,
// or completing a handshake. Probers never send credentials.
package proto

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Observation is the outcome of a single protocol probe.
type Observation struct {
	// Service is the canonical service name, for example "http".
	Service string
	// Product is the software implementation, for example "nginx".
	Product string
	// Version is the detected version string.
	Version string
	// Extra carries additional vendor or build information.
	Extra string
	// Banner is the raw banner text, trimmed for display.
	Banner string
	// Raw holds every byte read during the probe.
	Raw []byte
	// HTTP is populated for HTTP and HTTPS services.
	HTTP *HTTPInfo
	// TLS is populated for services negotiated over TLS.
	TLS *TLSInfo
	// JA3 is the MD5 fingerprint of the ClientHello we sent.
	JA3 string
	// JA3S is the MD5 fingerprint of the ServerHello we received.
	JA3S string
}

// Prober performs a protocol specific exchange over an established
// connection.
type Prober interface {
	// Name is the canonical service name.
	Name() string
	// Greeting reports whether the server speaks before the client. When
	// true the prober reads a banner first instead of sending a payload.
	Greeting() bool
	// Probe performs the exchange. A non-nil error means the service did
	// not speak the expected protocol.
	Probe(ctx context.Context, c net.Conn, ap netip.AddrPort, o Options) (*Observation, error)
}

// Options configures a probe run.
type Options struct {
	// Timeout bounds the whole exchange.
	Timeout time.Duration
	// UserAgent is sent with HTTP requests.
	UserAgent string
	// EnableJA3 turns on TLS handshake fingerprinting.
	EnableJA3 bool
	// EnableHTTP allows HTTP probing to run.
	EnableHTTP bool
	// EnableFavicon allows favicon hash collection.
	EnableFavicon bool
	// HostHeader overrides the Host header used for HTTP requests.
	HostHeader string
}

// DefaultUserAgent is used when no user agent is configured.
const DefaultUserAgent = "Mozilla/5.0 (compatible; vantage/1.0; +https://github.com/darkLabz001/darksec-recon-suite/vantage)"

var registry = map[string]Prober{}

// Register adds a prober to the registry.
func Register(p Prober) { registry[p.Name()] = p }

// Lookup returns the prober registered under name.
func Lookup(name string) (Prober, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names returns the sorted names of all registered probers.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// portProtocols maps well known ports to the protocols worth probing.
// The order of each list is the order in which the protocols are tried.
//
// Only the connection oriented protocols appear here. The services that
// exist solely over UDP, such as DHCP, TFTP and SSDP, are handled by the
// UDP engine, which identifies them from the shape of the answer.
var portProtocols = map[uint16][]string{
	21:    {"ftp"},
	22:    {"ssh"},
	23:    {"telnet"},
	25:    {"smtp"},
	53:    {"dns"},
	79:    {"http"},
	80:    {"http"},
	110:   {"pop3"},
	111:   {"rpcbind"},
	123:   {"ntp"},
	135:   {"msrpc"},
	137:   {"netbios"},
	139:   {"netbios"},
	143:   {"imap"},
	161:   {"snmp"},
	179:   {"bgp"},
	389:   {"ldap"},
	443:   {"https"},
	445:   {"smb"},
	465:   {"smtps"},
	514:   {"syslog"},
	515:   {"printer"},
	587:   {"smtp"},
	631:   {"ipp"},
	636:   {"ldaps"},
	993:   {"imaps"},
	995:   {"pop3s"},
	1080:  {"socks"},
	1194:  {"openvpn"},
	1433:  {"mssql"},
	1521:  {"oracle"},
	1883:  {"mqtt"},
	2049:  {"nfs"},
	2181:  {"zookeeper"},
	2375:  {"docker"},
	2376:  {"https"},
	3000:  {"http"},
	3268:  {"ldap"},
	3269:  {"ldaps"},
	3306:  {"mysql"},
	3389:  {"rdp"},
	4444:  {"http"},
	5000:  {"http"},
	5001:  {"http"},
	5060:  {"sip"},
	5061:  {"sip"},
	5222:  {"xmpp"},
	5432:  {"postgres"},
	5601:  {"http"},
	5672:  {"amqp"},
	5800:  {"vnc"},
	5900:  {"vnc"},
	5985:  {"http"},
	5986:  {"https"},
	6379:  {"redis"},
	6443:  {"https"},
	7001:  {"http"},
	7070:  {"http"},
	8000:  {"http"},
	8008:  {"http"},
	8009:  {"ajp13"},
	8080:  {"http"},
	8081:  {"http"},
	8088:  {"http"},
	8089:  {"http"},
	8443:  {"https"},
	8888:  {"http"},
	9000:  {"http"},
	9042:  {"cassandra"},
	9092:  {"kafka"},
	9200:  {"elasticsearch"},
	9300:  {"elasticsearch"},
	11211: {"memcached"},
	27017: {"mongodb"},
	27018: {"mongodb"},
	50070: {"http"},
}

// Candidates returns the protocol names to probe for the given port.
func Candidates(port uint16) []string {
	if list, ok := portProtocols[port]; ok {
		return list
	}
	return nil
}

// Known returns every port that has an associated protocol.
func Known() map[uint16][]string { return portProtocols }
