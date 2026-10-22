package lan

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestParseEthernet(t *testing.T) {
	frame := make([]byte, 14, 18)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeARP)
	frame = append(frame, 0xAA, 0xBB)

	f, err := ParseEthernet(frame)
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if f.Src.String() != "11:22:33:44:55:66" {
		t.Errorf("the source reads %q", f.Src)
	}
	if f.Type != EtherTypeARP {
		t.Errorf("the type reads %04x, want %04x", f.Type, EtherTypeARP)
	}
	if !bytes.Equal(f.Payload, []byte{0xAA, 0xBB}) {
		t.Errorf("the payload reads %x", f.Payload)
	}
}

func TestParseEthernetRejectsShortFrames(t *testing.T) {
	if _, err := ParseEthernet(make([]byte, 13)); err == nil {
		t.Fatal("a short frame must be rejected")
	}
}

func TestParseEthernetWithAVLANTag(t *testing.T) {
	frame := make([]byte, 18)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeVLAN)
	binary.BigEndian.PutUint16(frame[14:16], 0x0064) // the priority and the VLAN identifier
	binary.BigEndian.PutUint16(frame[16:18], EtherTypeIPv4)

	f, err := ParseEthernet(frame)
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if f.VLAN != 100 {
		t.Errorf("the VLAN reads %d, want 100", f.VLAN)
	}
	if f.Type != EtherTypeIPv4 {
		t.Errorf("the type reads %04x, want %04x", f.Type, EtherTypeIPv4)
	}
	if len(f.Payload) != 0 {
		t.Errorf("the payload reads %x", f.Payload)
	}
}

func TestParseEthernetRejectsATruncatedVLANTag(t *testing.T) {
	frame := make([]byte, 16)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeVLAN)
	if _, err := ParseEthernet(frame); err == nil {
		t.Fatal("a truncated VLAN tag must be rejected")
	}
}

func TestParseARP(t *testing.T) {
	body := make([]byte, 28)
	binary.BigEndian.PutUint16(body[0:2], 1) // the hardware type
	binary.BigEndian.PutUint16(body[2:4], 0x0800)
	body[4] = 6
	body[5] = 4
	binary.BigEndian.PutUint16(body[6:8], ARPRequest)
	copy(body[8:14], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(body[14:18], []byte{192, 0, 2, 10})
	copy(body[18:24], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	copy(body[24:28], []byte{192, 0, 2, 1})

	a, err := ParseARP(body)
	if err != nil {
		t.Fatalf("the frame must parse: %v", err)
	}
	if a.Op != ARPRequest {
		t.Errorf("the operation reads %d, want %d", a.Op, ARPRequest)
	}
	if a.SenderHW.String() != "11:22:33:44:55:66" {
		t.Errorf("the sender reads %q", a.SenderHW)
	}
	if a.SenderIP.String() != "192.0.2.10" {
		t.Errorf("the sender address reads %q", a.SenderIP)
	}
	if a.TargetIP.String() != "192.0.2.1" {
		t.Errorf("the target address reads %q", a.TargetIP)
	}
}

func TestParseARPRejectsBadFrames(t *testing.T) {
	if _, err := ParseARP(make([]byte, 4)); err == nil {
		t.Fatal("a short frame must be rejected")
	}
	body := make([]byte, 28)
	body[4] = 8 // a hardware address length of eight
	if _, err := ParseARP(body); err == nil {
		t.Fatal("a frame that is not Ethernet over IPv4 must be rejected")
	}
}

func TestParseDHCP(t *testing.T) {
	msg := make([]byte, 240)
	msg[0] = 2 // a reply
	msg[1] = 1 // the hardware type
	msg[2] = 6
	binary.BigEndian.PutUint32(msg[4:8], 0xDEADBEEF)
	copy(msg[16:20], []byte{192, 0, 2, 50})
	copy(msg[20:24], []byte{192, 0, 2, 1})
	copy(msg[28:34], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint32(msg[236:240], 0x63825363)

	// The message type, the server identifier, the router and the name
	// server.
	msg = append(msg, DHCPOptMessageType, 1, DHCPOFFER)
	msg = append(msg, DHCPOptServerID, 4, 192, 0, 2, 1)
	msg = append(msg, DHCPOptRouter, 4, 192, 0, 2, 1)
	msg = append(msg, DHCPOptDNSServers, 8, 8, 8, 8, 8, 1, 1, 1, 1)
	msg = append(msg, DHCPOptDomainName, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e')
	msg = append(msg, DHCPOptLeaseTime, 4, 0, 0, 0x0E, 0x10)
	msg = append(msg, 255)

	d, err := ParseDHCP(msg)
	if err != nil {
		t.Fatalf("the message must parse: %v", err)
	}
	if d.Op != 2 {
		t.Errorf("the operation reads %d, want 2", d.Op)
	}
	if d.MessageType != DHCPOFFER {
		t.Errorf("the message type reads %d, want %d", d.MessageType, DHCPOFFER)
	}
	if d.ServerIdentifier.String() != "192.0.2.1" {
		t.Errorf("the server identifier reads %q", d.ServerIdentifier)
	}
	if len(d.Router) != 1 || d.Router[0].String() != "192.0.2.1" {
		t.Errorf("the routers read %v", d.Router)
	}
	if len(d.DNS) != 2 {
		t.Errorf("the name servers read %v", d.DNS)
	}
	if d.DomainName != "example" {
		t.Errorf("the domain reads %q", d.DomainName)
	}
	if d.LeaseTime != 3600 {
		t.Errorf("the lease time reads %d, want 3600", d.LeaseTime)
	}
	if d.ClientMAC.String() != "11:22:33:44:55:66" {
		t.Errorf("the client reads %q", d.ClientMAC)
	}
	if d.YourIP.String() != "192.0.2.50" {
		t.Errorf("the address reads %q", d.YourIP)
	}
	if len(d.OptionOrder) == 0 {
		t.Error("the options carry no order")
	}
}

func TestParseDHCPRejectsBadMessages(t *testing.T) {
	if _, err := ParseDHCP(make([]byte, 100)); err == nil {
		t.Fatal("a short message must be rejected")
	}
	msg := make([]byte, 240)
	if _, err := ParseDHCP(msg); err == nil {
		t.Fatal("a message without a magic cookie must be rejected")
	}
}

func TestMessageTypeName(t *testing.T) {
	cases := map[uint8]string{
		DHCPDISCOVER: "DISCOVER",
		DHCPOFFER:    "OFFER",
		DHCPREQUEST:  "REQUEST",
		DHCPACK:      "ACK",
		DHCPNACK:     "NAK",
	}
	for typ, want := range cases {
		if got := MessageTypeName(typ); got != want {
			t.Errorf("the type %d reads %q, want %q", typ, got, want)
		}
	}
	if got := MessageTypeName(200); got == "" {
		t.Error("an unknown type must still be rendered")
	}
}

func TestParseDNS(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180) // a response, recursion available
	binary.BigEndian.PutUint16(msg[4:6], 1)      // one question
	binary.BigEndian.PutUint16(msg[6:8], 1)      // one answer

	// The question: www.example.org of type A.
	msg = append(msg, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0)
	msg = binary.BigEndian.AppendUint16(msg, DNSTypeA)
	msg = binary.BigEndian.AppendUint16(msg, DNSTypeA)

	// The answer: a pointer back to the name of the question.
	msg = binary.BigEndian.AppendUint16(msg, 0xC00C)
	msg = binary.BigEndian.AppendUint16(msg, DNSTypeA)
	msg = binary.BigEndian.AppendUint16(msg, 0) // the class
	msg = binary.BigEndian.AppendUint32(msg, 300)
	msg = binary.BigEndian.AppendUint16(msg, 4)
	msg = append(msg, 93, 184, 216, 34)

	d, err := ParseDNS(msg)
	if err != nil {
		t.Fatalf("the message must parse: %v", err)
	}
	if d.ID != 0x1234 {
		t.Errorf("the identifier reads %04x, want 1234", d.ID)
	}
	if !d.Response {
		t.Error("the message is a response")
	}
	if len(d.Questions) != 1 {
		t.Fatalf("the message holds %d questions, want 1", len(d.Questions))
	}
	if d.Questions[0].Name != "www.example.org" {
		t.Errorf("the question reads %q", d.Questions[0].Name)
	}
	if d.Questions[0].Type != DNSTypeA {
		t.Errorf("the question type reads %d, want %d", d.Questions[0].Type, DNSTypeA)
	}
	if len(d.Answers) != 1 {
		t.Fatalf("the message holds %d answers, want 1", len(d.Answers))
	}
	if d.Answers[0].Name != "www.example.org" {
		t.Errorf("the answer reads %q", d.Answers[0].Name)
	}
	if d.Answers[0].TTL != 300 {
		t.Errorf("the answer lives for %d seconds, want 300", d.Answers[0].TTL)
	}
	if !net.IP(d.Answers[0].Data).Equal(net.IPv4(93, 184, 216, 34)) {
		t.Errorf("the answer reads %v", d.Answers[0].Data)
	}
}

func TestParseDNSRejectsShortMessages(t *testing.T) {
	if _, err := ParseDNS(make([]byte, 11)); err == nil {
		t.Fatal("a short message must be rejected")
	}
}

func TestParseDNSRejectsATruncatedName(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, 3, 'w', 'w', 'w')
	if _, err := ParseDNS(msg); err == nil {
		t.Fatal("a truncated name must be rejected")
	}
}
