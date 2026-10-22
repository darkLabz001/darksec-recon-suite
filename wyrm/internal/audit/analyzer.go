package audit

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dh"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/dot11"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/eap"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/lan"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/pcap"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/sae"
)

// EtherType values the auditor reacts to.
const (
	etherTypeEAPOL uint16 = 0x888E
	etherTypeARP   uint16 = 0x0806
	etherTypeIPv4  uint16 = 0x0800
)

// DeauthWindow is the window in which management frame floods are counted.
const DeauthWindow = 10 * time.Second

// DeauthThreshold is the number of management frame disassociations in the
// window that counts as a flood.
const DeauthThreshold = 10

// Analyzer builds the audit model out of captured packets.
type Analyzer struct {
	session *Session

	// sae holds the SAE handshake in flight per access point and station.
	sae map[string]*saeState
	// eapwd holds the EAP-pwd exchange in flight per server and client.
	eapwd map[string]*eapwdState
	// handshakes tracks the four way handshakes.
	handshakes map[string]*Handshake
	// scalars remembers the commit scalars that were seen, so that a reused
	// scalar can be spotted.
	scalars map[string]string
	// floods counts the management frame disassociations per target.
	floods map[string][]time.Time
}

// saeState is the state of one SAE handshake.
type saeState struct {
	bssid      string
	client     string
	group      *dh.Group
	groupID    uint16
	validation *dh.Validation
	scalar     string
	commits    int
	confirms   int
	token      bool
	at         time.Time
}

// eapwdState is the state of one EAP-pwd exchange.
type eapwdState struct {
	server         string
	client         string
	groupID        uint16
	group          *dh.Group
	requestElement []byte
	requestPass    []byte
	responseElem   []byte
	responsePass   []byte
	at             time.Time
}

// New returns an analyzer that fills a new session.
func New(source string) *Analyzer {
	return &Analyzer{
		session:    NewSession(source),
		sae:        map[string]*saeState{},
		eapwd:      map[string]*eapwdState{},
		handshakes: map[string]*Handshake{},
		scalars:    map[string]string{},
		floods:     map[string][]time.Time{},
	}
}

// Result returns the session that was built.
func (a *Analyzer) Result() *Session { return a.session }

// Packet feeds one captured packet into the model.
func (a *Analyzer) Packet(p *pcap.Packet) {
	s := a.session
	s.Stats.Packets++
	s.Stats.Bytes += len(p.Data)
	if s.Stats.FirstSeen.IsZero() {
		s.Stats.FirstSeen = p.Timestamp
	}
	s.Stats.LastSeen = p.Timestamp
	if s.Started.IsZero() || p.Timestamp.Before(s.Started) {
		s.Started = p.Timestamp
	}
	if p.Timestamp.After(s.Ended) {
		s.Ended = p.Timestamp
	}

	switch p.LinkType {
	case pcap.LinkTypeIEEE80211Radiotap, pcap.LinkTypeIEEE80211, pcap.LinkTypeIEEE80211Radio:
		a.dot11Packet(p)
	case pcap.LinkTypeEthernet:
		a.ethernetPacket(p, nil)
	}
}

// dot11Packet handles one 802.11 frame.
func (a *Analyzer) dot11Packet(p *pcap.Packet) {
	f, err := dot11.Parse(p.Data, p.Timestamp)
	if err != nil {
		return
	}
	s := a.session
	switch f.Header.Type {
	case dot11.TypeManagement:
		s.Stats.Management++
		a.managementFrame(f)
	case dot11.TypeData:
		s.Stats.Data++
		a.dataFrame(f)
	case dot11.TypeControl:
		s.Stats.Control++
	}
}

// managementFrame handles a management frame.
func (a *Analyzer) managementFrame(f *dot11.Frame) {
	s := a.session
	m, err := dot11.ParseManagement(f)
	if err != nil && len(f.Body) == 0 {
		return
	}
	if m == nil {
		return
	}
	bssid := macString(f.Header.Addr3)
	if bssid == "" {
		bssid = macString(f.Header.Addr2)
	}

	switch f.Header.Subtype {
	case dot11.MgmtBeacon:
		s.Stats.Beacons++
		a.observeAP(f, m, bssid)
	case dot11.MgmtProbeResp:
		s.Stats.ProbeResponses++
		a.observeAP(f, m, bssid)
	case dot11.MgmtProbeReq:
		s.Stats.ProbeRequests++
		a.observeClient(f.Header.Addr2)
	case dot11.MgmtAuth:
		s.Stats.Auths++
		a.observeClient(f.Header.Addr1)
		a.observeClient(f.Header.Addr2)
		a.authenticationFrame(f, m, bssid)
	case dot11.MgmtAssocReq, dot11.MgmtReassocReq:
		s.Stats.Assocs++
		a.observeClient(f.Header.Addr2)
	case dot11.MgmtAssocResp:
		a.observeClient(f.Header.Addr1)
	case dot11.MgmtDeauth:
		s.Stats.Deauths++
		a.disassociation(f, bssid)
	case dot11.MgmtDisassoc:
		s.Stats.Disassocs++
		a.disassociation(f, bssid)
	case dot11.MgmtAction, dot11.MgmtActionNoAck:
		s.Stats.Actions++
		if hasCSA(m.Elements) {
			s.Stats.CSAs++
		}
	}
}

// observeAP records or refreshes an access point.
func (a *Analyzer) observeAP(f *dot11.Frame, m *dot11.Management, bssid string) {
	s := a.session
	ap, ok := s.APs[bssid]
	if !ok {
		ap = &AP{BSSID: bssid, FirstSeen: f.Timestamp}
		s.APs[bssid] = ap
	}
	if f.Header.Subtype == dot11.MgmtBeacon {
		ap.Beacons++
	} else {
		ap.Probes++
	}
	if f.Timestamp.After(ap.LastSeen) {
		ap.LastSeen = f.Timestamp
	}
	if f.Radiotap.HasChannel && f.Radiotap.Channel > 0 {
		ap.Channel = f.Radiotap.Channel
		ap.Frequency = f.Radiotap.Frequency
	} else if ch := m.ChannelOf(); ch > 0 {
		ap.Channel = ch
	}
	if f.Radiotap.HasRSSI {
		ap.Signal = int(f.Radiotap.Signal)
		ap.HasSignal = true
	}
	ssid := dot11.SSIDOf(m.Elements)
	if ssid != "" {
		ap.SSID = ssid
		ap.Hidden = false
	} else if dot11.HiddenSSID(m.Elements) {
		ap.Hidden = true
	}
	ap.Elements = m.Elements

	if rsn, ok := m.RSN(); ok {
		ap.RSN = rsn
	}
	if rsn, ok := m.WPAVendorRSN(); ok {
		ap.VendorRSN = rsn
	}
	if e, ok := dot11.Find(m.Elements, dot11.IEExtendedCaps); ok {
		ap.ExtCaps = e.Data
		ap.SAEPasswordsExclusively = dot11.ExtCapBit(e.Data, dot11.ExtCapSAEPasswordsExclusiv)
		ap.SAEPasswordIdentifiers = dot11.ExtCapBit(e.Data, dot11.ExtCapSAEIdentifiersInUse)
		ap.SAEPKExclusively = dot11.ExtCapBit(e.Data, dot11.ExtCapSAEPKExclusively)
	}
	if e, ok := dot11.Find(m.Elements, dot11.IERSNXE); ok {
		ap.SAEPK = dot11.RSNXESAEPK(e.Data)
	}
	for _, e := range m.Elements {
		oui, subtype, ok := e.VendorInfo()
		if !ok || oui != dot11.WPA3OUI {
			continue
		}
		switch subtype {
		case dot11.WFASubtypeOWETransitionMode:
			ap.OWETransitionMode = true
		case dot11.WFASubtypeTransitionDisableKDE:
			ap.TransitionDisableKDE = true
		}
	}
	a.scoreAP(ap)
}

// scoreAP derives the security posture of an access point.
func (a *Analyzer) scoreAP(ap *AP) {
	sec := Security{}
	rsn := ap.RSN
	if ap.VendorRSN != nil && rsn == nil {
		rsn = ap.VendorRSN
	}
	if rsn == nil {
		sec.Open = true
	} else {
		sec.MFPC = rsn.MFPC()
		sec.MFPR = rsn.MFPR()
		sec.SAEPK = ap.SAEPKExclusively || ap.SAEPK
		sec.GroupCipher = rsn.GroupCipher.Name()
		for _, c := range rsn.PairwiseCiphers {
			sec.Ciphers = append(sec.Ciphers, c.Name())
			if c.IsWeak() {
				sec.WEP = true
			}
		}
		for _, k := range rsn.AKMs {
			sec.AKMs = append(sec.AKMs, k.Name())
			switch {
			case k.IsSAE():
				sec.WPA3 = true
				sec.Personal = true
			case k.IsOWE():
				sec.OWE = true
			case k.IsPSKFamily():
				sec.WPA2 = true
				sec.Personal = true
			case k.IsEnterprise():
				sec.Enterprise = true
			}
		}
		if ap.VendorRSN != nil && rsn == ap.VendorRSN {
			sec.WPA1 = true
		}
		if sec.WPA3 && sec.WPA2 {
			sec.Transition = true
		}
	}
	if ap.OWETransitionMode {
		sec.Transition = true
	}
	sec.Score = ScoreSecurity(sec, ap)
	sec.Grade = gradeFor(sec.Score)
	ap.Security = sec
}

// authenticationFrame handles an authentication frame, which is where the
// SAE handshake lives.
func (a *Analyzer) authenticationFrame(f *dot11.Frame, m *dot11.Management, bssid string) {
	s := a.session
	if ap, ok := s.APs[bssid]; ok {
		ap.Auths++
	}
	if m.AuthAlgorithm != sae.AuthAlgorithmSAE {
		return
	}
	msg, err := sae.ParseAuth(f.Body)
	if err != nil {
		return
	}
	sender := macString(f.Header.Addr2)
	peer := macString(f.Header.Addr1)
	if sender == bssid {
		sender, peer = peer, sender
	}
	key := bssid + "|" + peer

	switch {
	case msg.IsCommit():
		s.Stats.SAECommits++
		st := a.sae[key]
		if st == nil {
			st = &saeState{bssid: bssid, client: peer, at: f.Timestamp}
			a.sae[key] = st
		}
		st.commits++
		st.at = f.Timestamp
		st.groupID = msg.GroupID
		st.group = msg.Group
		st.token = st.token || len(msg.AntiClog) > 0
		if msg.Group != nil {
			st.validation = sae.ValidateCommit(msg.Group, msg.Scalar, msg.Element)
		}
		if len(msg.Scalar) > 0 {
			st.scalar = hex.EncodeToString(msg.Scalar)
			if first, ok := a.scalars[st.scalar]; ok && first != key {
				s.AddFinding(Finding{
					ID:       "WYM-DFL-006",
					Title:    "A SAE commit scalar was reused",
					Severity: SeverityCritical,
					Family:   FamilyDragonfly,
					Target:   bssid,
					Detail: "The same commit scalar was seen in two different SAE handshakes, " +
						"which lets an observer recover the password verifier of the session.",
					Evidence: "the scalar first appeared in the handshake with " + first,
					Remedy:   "Rotate the network password and upgrade the access point firmware.",
					At:       f.Timestamp,
				})
			} else if !ok {
				a.scalars[st.scalar] = key
			}
		}
		a.recordSAE(st)
	case msg.IsConfirm():
		s.Stats.SAEConfirms++
		st := a.sae[key]
		if st == nil {
			st = &saeState{bssid: bssid, client: peer, at: f.Timestamp}
			a.sae[key] = st
		}
		st.confirms++
		st.at = f.Timestamp
		if st.group != nil {
			_ = msg.DecodeConfirm(st.group)
		}
		a.recordSAE(st)
	}
}

// recordSAE stores the state of an SAE handshake in the session.
func (a *Analyzer) recordSAE(st *saeState) {
	ex := SAEExchange{
		BSSID:      st.bssid,
		Client:     st.client,
		GroupID:    st.groupID,
		Group:      st.group,
		Validation: st.validation,
		Token:      st.token,
		Scalar:     st.scalar,
		Commits:    st.commits,
		Confirms:   st.confirms,
		At:         st.at,
	}
	for i := range a.session.SAE {
		if a.session.SAE[i].BSSID == ex.BSSID && a.session.SAE[i].Client == ex.Client {
			a.session.SAE[i] = ex
			return
		}
	}
	a.session.SAE = append(a.session.SAE, ex)
}

// disassociation records a deauthentication or disassociation frame.
func (a *Analyzer) disassociation(f *dot11.Frame, bssid string) {
	target := macString(f.Header.Addr1)
	key := bssid + "|" + target
	a.floods[key] = append(a.floods[key], f.Timestamp)
}

// observeClient records a client station.
func (a *Analyzer) observeClient(mac net.HardwareAddr) {
	name := macString(mac)
	if name == "" {
		return
	}
	s := a.session
	c, ok := s.Clients[name]
	if !ok {
		c = &Client{MAC: name, FirstSeen: s.Stats.FirstSeen, Networks: map[string]bool{}}
		s.Clients[name] = c
	}
	if s.Stats.LastSeen.After(c.LastSeen) {
		c.LastSeen = s.Stats.LastSeen
	}
}

// dataFrame handles a data frame.
func (a *Analyzer) dataFrame(f *dot11.Frame) {
	a.observeClient(f.Header.Addr1)
	a.observeClient(f.Header.Addr2)
	a.observeClient(f.Header.Addr3)
	if f.Header.Protected {
		// The payload is encrypted, so there is nothing to look at.
		return
	}
	eth := toEthernet(f)
	if eth == nil {
		return
	}
	a.ethernetFrame(eth, f.Timestamp)
}

// toEthernet rewrites an unprotected 802.11 data frame as an Ethernet frame.
func toEthernet(f *dot11.Frame) []byte {
	if len(f.Body) < 8 {
		return nil
	}
	// The payload carries an LLC/SNAP header.
	if f.Body[0] != 0xaa || f.Body[1] != 0xaa || f.Body[2] != 0x03 {
		return nil
	}
	ethType := binary.BigEndian.Uint16(f.Body[6:8])

	var src, dst net.HardwareAddr
	switch {
	case f.Header.FromDS && f.Header.ToDS:
		src, dst = f.Header.Addr4, f.Header.Addr3
	case f.Header.FromDS:
		src, dst = f.Header.Addr3, f.Header.Addr1
	case f.Header.ToDS:
		src, dst = f.Header.Addr2, f.Header.Addr3
	default:
		src, dst = f.Header.Addr2, f.Header.Addr1
	}
	if len(src) != 6 || len(dst) != 6 {
		return nil
	}
	out := make([]byte, 14, 14+len(f.Body)-8)
	copy(out[0:6], dst)
	copy(out[6:12], src)
	binary.BigEndian.PutUint16(out[12:14], ethType)
	out = append(out, f.Body[8:]...)
	return out
}

// ethernetPacket handles a packet that was captured on an Ethernet link.
func (a *Analyzer) ethernetPacket(p *pcap.Packet, _ *dot11.Frame) {
	a.ethernetFrame(p.Data, p.Timestamp)
}

// ethernetFrame handles an Ethernet frame.
func (a *Analyzer) ethernetFrame(data []byte, ts time.Time) {
	frame, err := lan.ParseEthernet(data)
	if err != nil {
		return
	}
	switch frame.Type {
	case etherTypeEAPOL:
		a.eapolFrame(frame, ts)
	case etherTypeARP:
		s := a.session
		s.Stats.ARPPackets++
		a.arpFrame(frame, ts)
	case etherTypeIPv4:
		a.ipv4Frame(frame, ts)
	}
}

// eapolFrame handles an 802.1X frame.
func (a *Analyzer) eapolFrame(frame *lan.Frame, ts time.Time) {
	s := a.session
	s.Stats.EAPOLFrames++
	ev, err := eap.ParseEAPOL(frame.Payload)
	if err != nil {
		return
	}
	if ev.Key != nil {
		a.eapolKey(frame, ev, ts)
		return
	}
	if ev.Packet == nil {
		return
	}
	p := ev.Packet
	if p.Type != eap.EAPTypePWD {
		return
	}
	w, err := eap.ParseEAPWD(p.Data)
	if err != nil {
		return
	}
	server := macString(frame.Src)
	client := macString(frame.Dst)
	key := server + "|" + client
	st := a.eapwd[key]
	if st == nil {
		st = &eapwdState{server: server, client: client, at: ts}
		a.eapwd[key] = st
	}
	st.groupID = w.GroupID
	st.group, _ = dh.GroupByID(w.GroupID)
	switch w.Opcode {
	case eap.EAPWDRequest:
		st.requestElement = append([]byte(nil), w.Element...)
		st.requestPass = append([]byte(nil), w.Password...)
		st.at = ts
	case eap.EAPWDResponse:
		st.responseElem = append([]byte(nil), w.Element...)
		st.responsePass = append([]byte(nil), w.Password...)
		st.at = ts
	}
	a.recordEAPPwd(st)
}

// recordEAPPwd stores an EAP-pwd exchange in the session.
func (a *Analyzer) recordEAPPwd(st *eapwdState) {
	ex := EAPPwdExchange{
		Server:       st.server,
		Client:       st.client,
		GroupID:      st.groupID,
		Group:        st.group,
		Request:      st.requestPass,
		Response:     st.responsePass,
		RequestElem:  st.requestElement,
		ResponseElem: st.responseElem,
		At:           st.at,
	}
	if len(st.requestPass) > 0 && len(st.responsePass) > 0 {
		ex.Reflect = eap.SameBytes(st.requestPass, st.responsePass)
	}
	for i := range a.session.EAPPwd {
		if a.session.EAPPwd[i].Server == ex.Server && a.session.EAPPwd[i].Client == ex.Client {
			a.session.EAPPwd[i] = ex
			return
		}
	}
	a.session.EAPPwd = append(a.session.EAPPwd, ex)
}

// eapolKey handles an EAPOL-Key frame, which carries the four way handshake.
func (a *Analyzer) eapolKey(frame *lan.Frame, ev *eap.EAPOL, ts time.Time) {
	s := a.session
	k := ev.Key
	src := macString(frame.Src)
	dst := macString(frame.Dst)

	// The access point sends message one and three, the station sends two
	// and four.  The handshake is tracked per access point and station.
	ap, client := dst, src
	if k.KeyNumber() == 1 || k.KeyNumber() == 3 {
		ap, client = src, dst
	}
	hkey := ap + "|" + client
	entry, exists := a.handshakes[hkey]
	if !exists {
		entry = &Handshake{BSSID: ap, Client: client, At: ts}
		a.handshakes[hkey] = entry
	}
	if ts.After(entry.At) {
		entry.At = ts
	}
	if entry.Messages == 0 || k.KeyNumber() > entry.Messages {
		entry.Messages = k.KeyNumber()
	}
	entry.Complete = entry.Messages >= 3

	// A PMKID in the key data allows an offline attack without the
	// handshake, so it is worth reporting on its own.
	if len(k.KeyData) > 0 {
		if rsn, ok := parseKeyDataRSN(k.KeyData); ok && len(rsn.PMKIDs) > 0 {
			entry.PMKID = rsn.PMKIDs[0]
		}
	}
	if entry.Complete && !containsHandshake(s.Handshakes, *entry) {
		s.Stats.Handshakes++
		s.Handshakes = append(s.Handshakes, *entry)
	}
}

// parseKeyDataRSN decodes an RSN element out of the key data of an
// EAPOL-Key frame.
func parseKeyDataRSN(data []byte) (*dot11.RSNInfo, bool) {
	els := dot11.ParseElements(data)
	e, ok := dot11.Find(els, dot11.IERSN)
	if !ok {
		return nil, false
	}
	r, err := dot11.ParseRSN(e.Data)
	if err != nil {
		return nil, false
	}
	return r, true
}

func containsHandshake(list []Handshake, h Handshake) bool {
	for _, x := range list {
		if x.BSSID == h.BSSID && x.Client == h.Client {
			return true
		}
	}
	return false
}

// arpFrame handles an ARP frame.
func (a *Analyzer) arpFrame(frame *lan.Frame, ts time.Time) {
	p, err := lan.ParseARP(frame.Payload)
	if err != nil {
		return
	}
	s := a.session
	ip := p.SenderIP.String()
	mac := macString(p.SenderHW)
	if ip == "<nil>" || mac == "" {
		return
	}
	m, ok := s.ARP[ip]
	if !ok {
		m = &ARPMapping{IP: ip, MAC: mac, FirstSeen: ts}
		s.ARP[ip] = m
	}
	m.Claims++
	if ts.After(m.LastSeen) {
		m.LastSeen = ts
	}
	if m.MAC != mac {
		// The address was claimed by a different hardware address.
		s.AddFinding(Finding{
			ID:       "WYM-LAN-001",
			Title:    "An address was claimed by two hardware addresses",
			Severity: SeverityCritical,
			Family:   FamilyLAN,
			Target:   ip,
			Detail: "Two hardware addresses answered for the same address, which is the " +
				"signature of an ARP poisoning attack.",
			Evidence: fmt.Sprintf("%s first, %s afterwards", m.MAC, mac),
			Remedy:   "Isolate the offending station and check the clients for static ARP entries.",
			At:       ts,
		})
	}
}

// ipv4Frame handles an IPv4 frame, which is where DHCP and DNS live.
func (a *Analyzer) ipv4Frame(frame *lan.Frame, ts time.Time) {
	payload := frame.Payload
	if len(payload) < 20 {
		return
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return
	}
	proto := payload[9]
	switch proto {
	case 17: // UDP
		if len(payload) < ihl+8 {
			return
		}
		udp := payload[ihl:]
		srcPort := binary.BigEndian.Uint16(udp[0:2])
		dstPort := binary.BigEndian.Uint16(udp[2:4])
		body := udp[8:]
		switch {
		case dstPort == 67 || srcPort == 67:
			a.dhcpFrame(body, ts)
		case dstPort == 53 || srcPort == 53:
			a.dnsFrame(body, ts)
		}
	}
}

// dhcpFrame handles a DHCP message.
func (a *Analyzer) dhcpFrame(data []byte, ts time.Time) {
	d, err := lan.ParseDHCP(data)
	if err != nil {
		return
	}
	s := a.session
	s.Stats.DHCPPackets++
	server := ""
	if d.ServerIdentifier != nil {
		server = d.ServerIdentifier.String()
	} else if d.ServerIP != nil && !d.ServerIP.IsUnspecified() {
		server = d.ServerIP.String()
	}
	if server == "" {
		return
	}
	s.DHCPServer[server] = true
}

// dnsFrame handles a DNS message.
func (a *Analyzer) dnsFrame(data []byte, ts time.Time) {
	if _, err := lan.ParseDNS(data); err != nil {
		return
	}
	s := a.session
	s.Stats.DNSPackets++
}

// hasCSA reports whether the elements carry a channel switch announcement.
func hasCSA(els []dot11.Element) bool {
	_, ok := dot11.Find(els, dot11.IEChannelSwitchAnn)
	return ok
}

// macString renders a hardware address.
func macString(m net.HardwareAddr) string {
	if len(m) == 0 {
		return ""
	}
	return m.String()
}

// vendorPrefix returns the organisation identifier of a hardware address.
func vendorPrefix(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.ToUpper(parts[0] + ":" + parts[1] + ":" + parts[2])
}

// sortedFloods returns the management frame flood counters, worst first.
func (a *Analyzer) sortedFloods() []struct {
	Key   string
	Count int
} {
	type entry = struct {
		Key   string
		Count int
	}
	var out []entry
	for key, times := range a.floods {
		cut := times[len(times)-1].Add(-DeauthWindow)
		n := 0
		for _, t := range times {
			if t.After(cut) {
				n++
			}
		}
		if n > 0 {
			out = append(out, entry{Key: key, Count: n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}
