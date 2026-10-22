// Package lan decodes the layer 2 and layer 3 traffic that matters on an open
// or public wireless network: ARP, DHCP and DNS.
//
// The decoders are deliberately small and defensive; they only look at the
// fields that the auditor reports on.
package lan

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Ethernet frame types.
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeIPv6 uint16 = 0x86DD
	EtherTypeVLAN uint16 = 0x8100
)

// Frame is a decoded Ethernet frame.
type Frame struct {
	Dst     net.HardwareAddr
	Src     net.HardwareAddr
	Type    uint16
	VLAN    uint16
	Payload []byte
}

// ParseEthernet decodes an Ethernet frame.
func ParseEthernet(data []byte) (*Frame, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("lan: Ethernet frame too short (%d bytes)", len(data))
	}
	f := &Frame{
		Dst:  net.HardwareAddr(append([]byte(nil), data[0:6]...)),
		Src:  net.HardwareAddr(append([]byte(nil), data[6:12]...)),
		Type: binary.BigEndian.Uint16(data[12:14]),
	}
	p := data[14:]
	for f.Type == EtherTypeVLAN {
		if len(p) < 4 {
			return f, fmt.Errorf("lan: truncated VLAN tag")
		}
		f.VLAN = binary.BigEndian.Uint16(p[0:2]) & 0x0FFF
		f.Type = binary.BigEndian.Uint16(p[2:4])
		p = p[4:]
	}
	f.Payload = p
	return f, nil
}

// ARP operation codes.
const (
	ARPRequest uint16 = 1
	ARPReply   uint16 = 2
)

// ARP is a decoded ARP frame.
type ARP struct {
	HWType   uint16
	Proto    uint16
	HWLen    uint8
	ProtoLen uint8
	Op       uint16
	SenderHW net.HardwareAddr
	SenderIP net.IP
	TargetHW net.HardwareAddr
	TargetIP net.IP
}

// ParseARP decodes an ARP frame for IPv4 over Ethernet.
func ParseARP(data []byte) (*ARP, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("lan: ARP frame too short (%d bytes)", len(data))
	}
	a := &ARP{
		HWType:   binary.BigEndian.Uint16(data[0:2]),
		Proto:    binary.BigEndian.Uint16(data[2:4]),
		HWLen:    data[4],
		ProtoLen: data[5],
		Op:       binary.BigEndian.Uint16(data[6:8]),
	}
	if a.HWLen != 6 || a.ProtoLen != 4 {
		return a, fmt.Errorf("lan: ARP frame is not Ethernet over IPv4")
	}
	if len(data) < 28 {
		return a, fmt.Errorf("lan: ARP frame is truncated")
	}
	a.SenderHW = net.HardwareAddr(append([]byte(nil), data[8:14]...))
	a.SenderIP = net.IP(append([]byte(nil), data[14:18]...))
	a.TargetHW = net.HardwareAddr(append([]byte(nil), data[18:24]...))
	a.TargetIP = net.IP(append([]byte(nil), data[24:28]...))
	return a, nil
}

// DHCP message types.
const (
	DHCPDISCOVER uint8 = 1
	DHCPOFFER    uint8 = 2
	DHCPREQUEST  uint8 = 3
	DHCPDECLINE  uint8 = 4
	DHCPACK      uint8 = 5
	DHCPNACK     uint8 = 6
	DHCPRELEASE  uint8 = 7
	DHCPINFORM   uint8 = 8
)

// DHCP is a decoded DHCP message.
type DHCP struct {
	Op               uint8
	HWType           uint8
	HWLen            uint8
	XID              uint32
	Flags            uint16
	ClientIP         net.IP
	YourIP           net.IP
	ServerIP         net.IP
	RelayIP          net.IP
	ClientMAC        net.HardwareAddr
	MessageType      uint8
	ServerIdentifier net.IP
	Router           []net.IP
	DNS              []net.IP
	DomainName       string
	LeaseTime        uint32
	Options          map[uint8][]byte
	OptionOrder      []uint8
}

// DHCP option codes the auditor reports on.
const (
	DHCPOptSubnetMask   uint8 = 1
	DHCPOptRouter       uint8 = 3
	DHCPOptDNSServers   uint8 = 6
	DHCPOptHostName     uint8 = 12
	DHCPOptDomainName   uint8 = 15
	DHCPOptVendorClass  uint8 = 60
	DHCPOptNTPServers   uint8 = 42
	DHCPOptPXE          uint8 = 43
	DHCPOptLeaseTime    uint8 = 51
	DHCPOptMessageType  uint8 = 53
	DHCPOptServerID     uint8 = 54
	DHCPOptParamRequest uint8 = 55
	DHCPOptMessage      uint8 = 56
	DHCPOptClientID     uint8 = 61
	DHCPOptRelayAgent   uint8 = 82
	DHCPOptUserClass    uint8 = 77
)

// ParseDHCP decodes a DHCP message.
func ParseDHCP(data []byte) (*DHCP, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("lan: DHCP message too short (%d bytes)", len(data))
	}
	d := &DHCP{
		Op:       data[0],
		HWType:   data[1],
		HWLen:    data[2],
		XID:      binary.BigEndian.Uint32(data[4:8]),
		Flags:    binary.BigEndian.Uint16(data[10:12]),
		ClientIP: net.IP(append([]byte(nil), data[12:16]...)),
		YourIP:   net.IP(append([]byte(nil), data[16:20]...)),
		ServerIP: net.IP(append([]byte(nil), data[20:24]...)),
		RelayIP:  net.IP(append([]byte(nil), data[24:28]...)),
		Options:  map[uint8][]byte{},
	}
	hwLen := int(d.HWLen)
	if hwLen > 16 {
		hwLen = 16
	}
	d.ClientMAC = net.HardwareAddr(append([]byte(nil), data[28:28+hwLen]...))

	if binary.BigEndian.Uint32(data[236:240]) != 0x63825363 {
		return d, fmt.Errorf("lan: DHCP message has no magic cookie")
	}
	p := 240
	for p < len(data) {
		code := data[p]
		if code == 0 { // pad
			p++
			continue
		}
		if code == 255 { // end
			break
		}
		if p+1 >= len(data) {
			break
		}
		ln := int(data[p+1])
		if p+2+ln > len(data) {
			break
		}
		val := append([]byte(nil), data[p+2:p+2+ln]...)
		if _, seen := d.Options[code]; !seen {
			d.OptionOrder = append(d.OptionOrder, code)
		}
		d.Options[code] = val
		switch code {
		case DHCPOptMessageType:
			if len(val) >= 1 {
				d.MessageType = val[0]
			}
		case DHCPOptServerID:
			if len(val) >= 4 {
				d.ServerIdentifier = net.IP(append([]byte(nil), val[0:4]...))
			}
		case DHCPOptRouter:
			for i := 0; i+4 <= len(val); i += 4 {
				d.Router = append(d.Router, net.IP(append([]byte(nil), val[i:i+4]...)))
			}
		case DHCPOptDNSServers:
			for i := 0; i+4 <= len(val); i += 4 {
				d.DNS = append(d.DNS, net.IP(append([]byte(nil), val[i:i+4]...)))
			}
		case DHCPOptDomainName:
			d.DomainName = string(val)
		case DHCPOptLeaseTime:
			if len(val) >= 4 {
				d.LeaseTime = binary.BigEndian.Uint32(val[0:4])
			}
		}
		p += 2 + ln
	}
	return d, nil
}

// MessageTypeName renders a DHCP message type.
func MessageTypeName(t uint8) string {
	switch t {
	case DHCPDISCOVER:
		return "DISCOVER"
	case DHCPOFFER:
		return "OFFER"
	case DHCPREQUEST:
		return "REQUEST"
	case DHCPDECLINE:
		return "DECLINE"
	case DHCPACK:
		return "ACK"
	case DHCPNACK:
		return "NAK"
	case DHCPRELEASE:
		return "RELEASE"
	case DHCPINFORM:
		return "INFORM"
	}
	return fmt.Sprintf("type %d", t)
}

// DNS is a decoded DNS message.
type DNS struct {
	ID        uint16
	Response  bool
	Opcode    uint8
	RCode     uint8
	Questions []DNSQuestion
	Answers   []DNSRecord
}

// DNSQuestion is one question of a DNS message.
type DNSQuestion struct {
	Name string
	Type uint16
}

// DNSRecord is one answer of a DNS message.
type DNSRecord struct {
	Name string
	Type uint16
	TTL  uint32
	Data []byte
}

// DNS record types.
const (
	DNSTypeA     uint16 = 1
	DNSTypeAAAA  uint16 = 28
	DNSTypeCNAME uint16 = 5
)

// ParseDNS decodes a DNS message.
func ParseDNS(data []byte) (*DNS, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("lan: DNS message too short (%d bytes)", len(data))
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	d := &DNS{
		ID:       binary.BigEndian.Uint16(data[0:2]),
		Response: flags&0x8000 != 0,
		Opcode:   uint8((flags >> 11) & 0x0F),
		RCode:    uint8(flags & 0x0F),
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	p := 12
	for i := 0; i < qd; i++ {
		name, next, err := readName(data, p)
		if err != nil {
			return d, err
		}
		p = next
		if p+4 > len(data) {
			return d, fmt.Errorf("lan: DNS question is truncated")
		}
		d.Questions = append(d.Questions, DNSQuestion{
			Name: name,
			Type: binary.BigEndian.Uint16(data[p : p+2]),
		})
		p += 4
	}
	for i := 0; i < an; i++ {
		name, next, err := readName(data, p)
		if err != nil {
			return d, err
		}
		p = next
		if p+10 > len(data) {
			return d, fmt.Errorf("lan: DNS answer is truncated")
		}
		rec := DNSRecord{
			Name: name,
			Type: binary.BigEndian.Uint16(data[p : p+2]),
			TTL:  binary.BigEndian.Uint32(data[p+4 : p+8]),
		}
		rdlen := int(binary.BigEndian.Uint16(data[p+8 : p+10]))
		p += 10
		if p+rdlen > len(data) {
			return d, fmt.Errorf("lan: DNS record data is truncated")
		}
		rec.Data = append([]byte(nil), data[p:p+rdlen]...)
		p += rdlen
		d.Answers = append(d.Answers, rec)
	}
	return d, nil
}

// readName reads a DNS name, following compression pointers.
//
// The offset that is returned is the one that follows the name in the
// message, so a name that ends in a compression pointer gives the position
// after the pointer and a name that is written out in full gives the
// position after its terminating zero.
func readName(data []byte, off int) (string, int, error) {
	var sb strings.Builder
	seen := 0
	next := -1
	for {
		if off >= len(data) {
			return "", 0, fmt.Errorf("lan: DNS name is truncated")
		}
		l := int(data[off])
		if l == 0 {
			off++
			if next < 0 {
				next = off
			}
			break
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(data) {
				return "", 0, fmt.Errorf("lan: DNS compression pointer is truncated")
			}
			ptr := int(binary.BigEndian.Uint16(data[off:off+2]) & 0x3FFF)
			if next < 0 {
				next = off + 2
			}
			seen++
			if seen > 16 {
				return "", 0, fmt.Errorf("lan: DNS compression pointer loop")
			}
			off = ptr
			continue
		}
		if off+1+l > len(data) {
			return "", 0, fmt.Errorf("lan: DNS label is truncated")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(data[off+1 : off+1+l])
		off += 1 + l
	}
	return sb.String(), next, nil
}
