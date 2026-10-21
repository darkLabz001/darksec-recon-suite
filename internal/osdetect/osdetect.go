// Package osdetect identifies a remote operating system by fingerprinting
// its TCP/IP stack.
//
// A crafted SYN is sent to an open port and the SYN-ACK is dissected: the
// initial time-to-live, the TCP window size, the maximum segment size and
// the ordered list of TCP options (window scale, SACK, timestamps) are all
// distinctive per operating system. The observed signature is compared
// against a built-in database and the closest match is reported together
// with the raw values, so the guess can be verified by eye.
package osdetect

import (
	"net/netip"
)

// Fingerprint is the TCP/IP stack signature observed in a SYN-ACK.
type Fingerprint struct {
	// TTL is the observed time-to-live of the reply.
	TTL uint8 `json:"ttl"`
	// InitialTTL is the observed TTL rounded up to the nearest common
	// initial value (64, 128 or 255), which cancels out the number of
	// hops between the scanner and the target.
	InitialTTL uint8 `json:"initial_ttl"`
	// Window is the TCP receive window advertised by the target.
	Window uint16 `json:"window"`
	// MSS is the maximum segment size the target accepts.
	MSS uint16 `json:"mss"`
	// WindowScale is the window scale factor, or -1 when absent.
	WindowScale int `json:"window_scale"`
	// SACKOK reports whether the target supports selective acknowledgements.
	SACKOK bool `json:"sack_ok"`
	// Timestamp reports whether the target sends TCP timestamps.
	Timestamp bool `json:"timestamp"`
	// IPID is the IPv4 identification field of the reply.
	IPID uint16 `json:"ip_id"`
	// Options is the ordered list of options, for example
	// "MSS,SACKOK,TS,NOP,WScale".
	Options string `json:"options"`
}

// Match is one candidate operating system.
type Match struct {
	// Name is the operating system family, for example "Linux".
	Name string `json:"name"`
	// Description is a human readable elaboration, for example
	// "Linux 5.x/6.x (Ubuntu, Debian, Arch, Fedora)".
	Description string `json:"description"`
	// Accuracy is a rough confidence score from 0 to 100.
	Accuracy int `json:"accuracy"`
}

// Result is the outcome of probing one host.
type Result struct {
	// Addr is the address that was fingerprinted.
	Addr netip.Addr `json:"addr"`
	// OS is the best guess, empty when nothing matched confidently.
	OS string `json:"os"`
	// Description elaborates on the guess.
	Description string `json:"description,omitempty"`
	// Accuracy is the confidence in the guess, from 0 to 100.
	Accuracy int `json:"accuracy"`
	// Fingerprint carries the raw values the guess was derived from.
	Fingerprint Fingerprint `json:"fingerprint"`
	// Candidates lists the closest database matches, best first.
	Candidates []Match `json:"candidates,omitempty"`
}

// initialTTL rounds an observed TTL up to the nearest common initial value.
func initialTTL(t uint8) uint8 {
	switch {
	case t <= 64:
		return 64
	case t <= 128:
		return 128
	default:
		return 255
	}
}
