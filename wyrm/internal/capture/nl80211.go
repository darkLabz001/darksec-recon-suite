// Package capture drives live wireless captures.
//
// Two things happen here.  The first is the capture itself, which is delegated
// to tcpdump writing a pcap stream to its standard output; the auditor parses
// that stream with its own pcap reader so that it needs neither libpcap nor
// cgo.  The second is the control of the radio, which is done over the
// nl80211 netlink interface directly, because the iw utility is not available
// on every host.
//
// The nl80211 constants used here were taken from the kernel headers in
// /usr/include/linux/nl80211.h.
package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// nl80211 attribute numbers.
const (
	nlAttrWiphy            uint16 = 1
	nlAttrIfIndex          uint16 = 3
	nlAttrIfName           uint16 = 4
	nlAttrIfType           uint16 = 5
	nlAttrWiphyFreq        uint16 = 38
	nlAttrWiphyChannelType uint16 = 39
	nlAttrWiphyFreqOffset  uint16 = 290
)

// nl80211 command numbers.
const (
	nlCmdGetWiphy uint8 = 1
	nlCmdSetWiphy uint8 = 2
	nlCmdGetIf    uint8 = 5
	nlCmdSetIf    uint8 = 6
)

// nl80211 interface types.
const (
	nlIfTypeStation uint32 = 2
	nlIfTypeMonitor uint32 = 6
)

// nl80211 channel types.
const (
	nlChanNoHT      uint8 = 0
	nlChanHT20      uint8 = 1
	nlChanHT40Minus uint8 = 2
	nlChanHT40Plus  uint8 = 3
)

// Netlink message layout.
const (
	nlmsgHdrLen  = 16
	genlHdrLen   = 4
	nlmsgRequest = 0x0001
	nlmsgAck     = 0x0004
	nlmsgDump    = 0x0300

	nlmsgDone  uint16 = 3
	nlmsgError uint16 = 2

	genlIDCtrl = 16

	ctrlCmdGetFamily   uint8  = 3
	ctrlAttrFamilyID   uint16 = 1
	ctrlAttrFamilyName uint16 = 2
)

// nl80211FamilyName is the generic netlink family name of the wireless
// subsystem.
const nl80211FamilyName = "nl80211"

// nlAttr is one netlink attribute.
type nlAttr struct {
	Type uint16
	Data []byte
}

// Radio controls a wireless interface over nl80211.
type Radio struct {
	fd       int
	familyID uint16
	seq      uint32
}

// OpenRadio opens a netlink generic socket and resolves the nl80211 family.
func OpenRadio() (*Radio, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_GENERIC)
	if err != nil {
		return nil, fmt.Errorf("capture: cannot open a netlink socket: %w", err)
	}
	r := &Radio{fd: fd}
	// Give the socket a receive timeout so that a lost reply cannot hang the
	// tool for ever.
	tv := syscall.NsecToTimeval(int64(5 * time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: cannot set the netlink timeout: %w", err)
	}
	family, err := r.lookupFamily(nl80211FamilyName)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	r.familyID = family
	return r, nil
}

// Close releases the netlink socket.
func (r *Radio) Close() error {
	if r.fd >= 0 {
		err := syscall.Close(r.fd)
		r.fd = -1
		return err
	}
	return nil
}

// buildMessage assembles a generic netlink request.
func (r *Radio) buildMessage(msgType uint16, flags uint16, cmd uint8, attrs []nlAttr) []byte {
	body := make([]byte, 0, 256)
	body = append(body, cmd, 0, 0, 0) // struct genlmsghdr
	for _, a := range attrs {
		l := 4 + len(a.Data)
		ab := make([]byte, l)
		binary.LittleEndian.PutUint16(ab[0:2], uint16(l))
		binary.LittleEndian.PutUint16(ab[2:4], a.Type)
		copy(ab[4:], a.Data)
		for len(ab)%4 != 0 {
			ab = append(ab, 0)
		}
		body = append(body, ab...)
	}
	r.seq++
	hdr := make([]byte, nlmsgHdrLen)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.LittleEndian.PutUint16(hdr[4:6], msgType)
	binary.LittleEndian.PutUint16(hdr[6:8], flags)
	binary.LittleEndian.PutUint32(hdr[8:12], r.seq)
	return append(hdr, body...)
}

// do sends a request and collects the replies.
func (r *Radio) do(msg []byte, dump bool) ([]byte, error) {
	if _, err := syscall.Write(r.fd, msg); err != nil {
		return nil, fmt.Errorf("capture: netlink write: %w", err)
	}
	buf := make([]byte, 1<<16)
	var out []byte
	for {
		n, _, err := syscall.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				return out, nil
			}
			return nil, fmt.Errorf("capture: netlink receive: %w", err)
		}
		chunk := buf[:n]
		for len(chunk) >= nlmsgHdrLen {
			l := int(binary.LittleEndian.Uint32(chunk[0:4]))
			if l < nlmsgHdrLen || l > len(chunk) {
				return nil, fmt.Errorf("capture: netlink message length %d is out of range", l)
			}
			typ := binary.LittleEndian.Uint16(chunk[4:6])
			payload := chunk[nlmsgHdrLen:l]
			switch typ {
			case nlmsgDone:
				return out, nil
			case nlmsgError:
				if len(payload) < 4 {
					return nil, fmt.Errorf("capture: short netlink error message")
				}
				code := int32(binary.LittleEndian.Uint32(payload[0:4]))
				if code == 0 {
					if !dump {
						return out, nil
					}
					break
				}
				return nil, fmt.Errorf("capture: netlink request failed: %s", syscall.Errno(-code))
			default:
				out = append(out, chunk[:l]...)
				if !dump {
					return out, nil
				}
			}
			chunk = chunk[l:]
		}
		if !dump {
			return out, nil
		}
	}
}

// lookupFamily resolves the generic netlink family identifier of a family.
func (r *Radio) lookupFamily(name string) (uint16, error) {
	msg := r.buildMessage(genlIDCtrl, nlmsgRequest, ctrlCmdGetFamily, []nlAttr{
		{Type: ctrlAttrFamilyName, Data: append([]byte(name), 0)},
	})
	data, err := r.do(msg, false)
	if err != nil {
		return 0, err
	}
	if len(data) < genlHdrLen {
		return 0, fmt.Errorf("capture: short netlink reply for family %s", name)
	}
	attrs, err := parseAttrs(data[genlHdrLen:])
	if err != nil {
		return 0, err
	}
	for _, a := range attrs {
		if a.Type == ctrlAttrFamilyID && len(a.Data) >= 2 {
			return binary.LittleEndian.Uint16(a.Data), nil
		}
	}
	return 0, fmt.Errorf("capture: the kernel did not return an identifier for family %s", name)
}

// parseAttrs decodes a stream of netlink attributes.
func parseAttrs(data []byte) ([]nlAttr, error) {
	var out []nlAttr
	for len(data) >= 4 {
		l := int(binary.LittleEndian.Uint16(data[0:2]))
		if l < 4 {
			return nil, fmt.Errorf("capture: netlink attribute length %d is out of range", l)
		}
		if l > len(data) {
			break
		}
		t := binary.LittleEndian.Uint16(data[2:4]) & 0x3fff
		out = append(out, nlAttr{Type: t, Data: data[4:l]})
		adv := l
		if adv%4 != 0 {
			adv += 4 - adv%4
		}
		if adv > len(data) {
			break
		}
		data = data[adv:]
	}
	return out, nil
}

// eachMessage walks a concatenated stream of netlink messages.
func eachMessage(data []byte, fn func(payload []byte) error) error {
	for len(data) >= nlmsgHdrLen {
		l := int(binary.LittleEndian.Uint32(data[0:4]))
		if l < nlmsgHdrLen || l > len(data) {
			return fmt.Errorf("capture: netlink message length %d is out of range", l)
		}
		if err := fn(data[nlmsgHdrLen:l]); err != nil {
			return err
		}
		data = data[l:]
	}
	return nil
}

// Interface describes one wireless interface.
type Interface struct {
	Name    string
	Index   int
	Wiphy   uint32
	IfType  uint32
	Monitor bool
}

// QueryInterface returns the nl80211 description of an interface.
func (r *Radio) QueryInterface(name string) (*Interface, error) {
	msg := r.buildMessage(r.familyID, nlmsgRequest|nlmsgDump, nlCmdGetIf, nil)
	data, err := r.do(msg, true)
	if err != nil {
		return nil, err
	}
	var found *Interface
	err = eachMessage(data, func(payload []byte) error {
		if len(payload) < genlHdrLen {
			return nil
		}
		attrs, err := parseAttrs(payload[genlHdrLen:])
		if err != nil {
			return nil
		}
		iface := &Interface{}
		ok := false
		for _, a := range attrs {
			switch a.Type {
			case nlAttrIfName:
				iface.Name = cstring(a.Data)
				ok = true
			case nlAttrIfIndex:
				if len(a.Data) >= 4 {
					iface.Index = int(binary.LittleEndian.Uint32(a.Data))
				}
			case nlAttrWiphy:
				if len(a.Data) >= 4 {
					iface.Wiphy = binary.LittleEndian.Uint32(a.Data)
				}
			case nlAttrIfType:
				if len(a.Data) >= 4 {
					iface.IfType = binary.LittleEndian.Uint32(a.Data)
				}
			}
		}
		if ok && iface.Name == name {
			found = iface
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("capture: the kernel does not know the interface %s", name)
	}
	found.Monitor = found.IfType == nlIfTypeMonitor
	return found, nil
}

// SetInterfaceType changes the type of an interface, which is how monitor
// mode is entered and left.
func (r *Radio) SetInterfaceType(ifindex int, iftype uint32) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(ifindex))
	tbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(tbuf, iftype)
	msg := r.buildMessage(r.familyID, nlmsgRequest|nlmsgAck, nlCmdSetIf, []nlAttr{
		{Type: nlAttrIfIndex, Data: buf},
		{Type: nlAttrIfType, Data: tbuf},
	})
	_, err := r.do(msg, false)
	if err != nil {
		return fmt.Errorf("capture: cannot change the interface type: %w", err)
	}
	return nil
}

// SetMonitor puts an interface into monitor mode.
func (r *Radio) SetMonitor(ifindex int) error {
	return r.SetInterfaceType(ifindex, nlIfTypeMonitor)
}

// SetManaged returns an interface to station mode.
func (r *Radio) SetManaged(ifindex int) error {
	return r.SetInterfaceType(ifindex, nlIfTypeStation)
}

// SetChannel moves a radio to a channel.
func (r *Radio) SetChannel(wiphy uint32, freqMHz uint32, chantype uint8) error {
	wbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(wbuf, wiphy)
	fbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(fbuf, freqMHz)
	cbuf := make([]byte, 4)
	cbuf[0] = chantype
	msg := r.buildMessage(r.familyID, nlmsgRequest|nlmsgAck, nlCmdSetWiphy, []nlAttr{
		{Type: nlAttrWiphy, Data: wbuf},
		{Type: nlAttrWiphyFreq, Data: fbuf},
		{Type: nlAttrWiphyChannelType, Data: cbuf},
	})
	_, err := r.do(msg, false)
	if err != nil {
		return fmt.Errorf("capture: cannot tune the radio to %d MHz: %w", freqMHz, err)
	}
	return nil
}

// InterfaceIndex returns the kernel index of an interface.
func InterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("capture: cannot look up the interface %s: %w", name, err)
	}
	return iface.Index, nil
}

// cstring turns a netlink string attribute into a Go string.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// IsRoot reports whether the process runs with root privileges, which the
// capture needs for monitor mode and raw sockets.
func IsRoot() bool { return os.Geteuid() == 0 }
