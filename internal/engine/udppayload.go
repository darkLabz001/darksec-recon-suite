package engine

import "strings"

// udpPayloads maps a UDP port to the datagram that is most likely to make
// the service answer. Ports that are not listed receive an empty datagram,
// which is enough to make a closed port answer with ICMP port unreachable.
var udpPayloads = map[uint16][]byte{
	7:     {}, // echo
	9:     {}, // discard
	19:    {}, // chargen
	53:    dnsVersionBind(),
	67:    dhcpDiscover(),
	68:    dhcpDiscover(),
	69:    tftpRead(),
	123:   ntpMonlist(),
	137:   netbiosNameQuery(),
	138:   netbiosNameQuery(),
	161:   snmpSysDescr(),
	162:   snmpSysDescr(),
	1900:  ssdpSearch(),
	4500:  ike(),
	5060:  sipOptions(),
	5353:  mdnsQuery(),
	623:   ipmiPing(),
	11211: memcachedUDP(),
}

// udpPayload returns the probe datagram for a port.
func udpPayload(port uint16) []byte {
	if p, ok := udpPayloads[port]; ok {
		return p
	}
	return nil
}

// dnsVersionBind builds a CHAOS class TXT query for "version.bind", which
// most DNS servers answer with the version of their implementation.
func dnsVersionBind() []byte {
	q := []byte{
		0x00, 0x1e, // transaction id
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
	}
	q = append(q, dnsName("version.bind")...)
	q = append(q, 0x00, 0x10) // TYPE TXT
	q = append(q, 0x00, 0x03) // CLASS CH
	return q
}

// dnsName encodes a domain name in the DNS wire format.
func dnsName(name string) []byte {
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

// dhcpDiscover builds a DHCPDISCOVER message.
func dhcpDiscover() []byte {
	m := []byte{
		0x01, 0x01, 0x06, 0x00, // op, htype, hlen, hops
		0x00, 0x00, 0x00, 0x00, // transaction id
		0x00, 0x00, 0x00, 0x00, // elapsed time, flags
		0x00, 0x00, 0x00, 0x00, // client address
		0x00, 0x00, 0x00, 0x00, // your address
		0x00, 0x00, 0x00, 0x00, // server address
		0x00, 0x00, 0x00, 0x00, // relay address
		0x00, 0x00, 0x00, 0x00, // client hardware address
	}
	m = append(m, 0x00, 0x00, 0x00, 0x00) // server host name
	m = append(m, 0x00, 0x00, 0x00, 0x00) // boot file name
	m = append(m, 0x00, 0x00, 0x00, 0x00) // magic cookie
	m = append(m, 0x35, 0x01, 0x01, 0x00) // option 53, DHCP discover
	m = append(m, 0xff)                   // end
	return m
}

// tftpRead builds a TFTP read request for an empty file name.
func tftpRead() []byte {
	m := []byte{0x00, 0x01} // opcode: read request
	m = append(m, "vantage"...)
	m = append(m, 0x00)
	m = append(m, "octet"...)
	m = append(m, 0x00)
	return m
}

// ntpMonlist builds the classic NTP monlist probe, which makes an old or
// misconfigured server disclose its client list.
func ntpMonlist() []byte {
	m := make([]byte, 48)
	m[0] = 0x17 // leap 0, version 2, mode 7 (private, monlist)
	return m
}

// netbiosNameQuery builds a NetBIOS name service node status request.
func netbiosNameQuery() []byte {
	m := []byte{
		0x00, 0x00, // transaction id
		0x00, 0x00, // flags: query
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
	}
	m = append(m, netbiosName("*")...)
	m = append(m, 0x00, 0x20) // type NB
	m = append(m, 0x00, 0x01) // class IN
	return m
}

// netbiosName encodes a NetBIOS name using the first level encoding.
func netbiosName(name string) []byte {
	raw := make([]byte, 16)
	copy(raw, name)
	for i := len(name); i < len(raw); i++ {
		raw[i] = ' '
	}
	out := make([]byte, 0, 34)
	out = append(out, byte(len(raw)*2))
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return append(out, 0x00)
}

// snmpSysDescr builds an SNMPv1 GetRequest for sysDescr.0 using the public
// community.
func snmpSysDescr() []byte {
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

// ssdpSearch builds an SSDP M-SEARCH datagram.
func ssdpSearch() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n")
}

// ike builds an IKEv1 SA proposal payload.
func ike() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, // initiator SPI
		0x00, 0x00, 0x00, 0x00, // responder SPI
		0x01,                   // next payload: SA
		0x02,                   // version 1
		0x34, 0x00, 0x00, 0x00, // exchange type: identity protection
		0x00, 0x00, 0x00, 0x00, // flags
		0x00, 0x00, 0x00, 0x00, // message id
		0x00, 0x00, 0x00, 0x00, // length
	}
}

// sipOptions builds a SIP OPTIONS request.
func sipOptions() []byte {
	return []byte("OPTIONS sip:vantage@invalid SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP vantage.invalid:5060;branch=z9hG4bK-vantage\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")
}

// mdnsQuery builds a multicast DNS service enumeration query.
func mdnsQuery() []byte {
	m := []byte{
		0x00, 0x00, // transaction id
		0x00, 0x00, // flags
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
	}
	m = append(m, 0x04, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 0x05, '_', 'l', 'o', 'c', 'a', 'l', 0x00)
	m = append(m, 0x00, 0x0c) // type PTR
	m = append(m, 0x00, 0x01) // class IN
	return m
}

// ipmiPing builds an IPMI presence ping.
func ipmiPing() []byte {
	m := []byte{0x06, 0x00, 0xff, 0x0f} // RMCP header
	return append(m, make([]byte, 20)...)
}

// memcachedUDP builds a memcached statistics request for the UDP variant of
// the protocol, which prefixes the request with an eight byte header.
func memcachedUDP() []byte {
	m := make([]byte, 8)
	m = append(m, "stats\r\n"...)
	return m
}
