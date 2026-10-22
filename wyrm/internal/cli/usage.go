package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/version"
)

// usage prints the help message.
func usage(w io.Writer) {
	fmt.Fprintf(w, `wyrm %s - a WPA3 and WPA2 wireless security auditor

Usage:
  wyrm gui                     launch the graphical interface
  wyrm survey                  capture for a while and list the access points
  wyrm watch                   capture for a while and report the findings
  wyrm analyze <capture.pcap>  audit a capture file
  wyrm check <capture.pcap>    audit a capture file and list the findings
  wyrm report <capture.pcap>   write a report of a capture file to a file
  wyrm iface                   list the wireless interfaces of the host

  wyrm survey -i wlp4s0 -c 1,6,11 --duration 60
  wyrm analyze capture.pcap --format json

The graphical interface:
  wyrm gui starts a local web server and opens it in a browser, so a
  capture can be configured and followed live without the command line. Use
  --listen to change the address (default 127.0.0.1:8788) and --no-open to
  skip opening a browser.

What is audited:
`, version.Version)

	families := []struct {
		name string
		desc string
	}{
		{audit.FamilyDowngrade, "transition mode, evil twins, open networks and the WPA2 handshake"},
		{audit.FamilyDragonfly, "SAE group strength, commit validation and side channels"},
		{audit.FamilyEAP, "the EAP-pwd method, invalid curve and reflection"},
		{audit.FamilyMgmt, "management frame flooding and channel switch announcements"},
		{audit.FamilyLAN, "address poisoning, rogue DHCP and the shared group key"},
	}
	for _, f := range families {
		fmt.Fprintf(w, "  %-12s %s\n", f.name, f.desc)
	}

	fmt.Fprint(w, `
Flags:
`)

	type flagLine struct {
		name string
		desc string
	}
	lines := []flagLine{
		{"-i, --interface", "wireless interface to use"},
		{"-c, --channels", "channels to use, for example 1,6,11 or 36-48"},
		{"    --hop", "hop over the channels (on by default)"},
		{"    --hop-interval", "time spent on each channel"},
		{"    --monitor", "switch the interface to monitor mode"},
		{"    --filter", "packet filter, for example \"type mgt\""},
		{"-o, --output", "file to write the capture or the report to"},
		{"    --format", "output format: text, json or html"},
		{"    --duration", "length of the capture (0 means until it is stopped)"},
		{"    --sudo-password", "password used to run the capture through sudo"},
		{"    --no-color", "disable coloured output"},
		{"    --quiet", "suppress progress information"},
		{"-v, --version", "print the version and exit"},
		{"-h, --help", "print this help and exit"},
	}

	for _, l := range lines {
		fmt.Fprintf(w, "  %-20s %s\n", l.name, l.desc)
	}

	fmt.Fprint(w, `
Notes:
  A capture needs root privileges or a password for sudo, because a raw
  wireless capture is not something an unprivileged process may do. The
  password can also be given in the WYRM_SUDO_PASSWORD environment
  variable.

  Monitor mode takes the interface off the network, so the connection that
  is using it will drop. It is never switched on without being asked for.

Examples:
  wyrm gui                                   the dashboard
  wyrm survey -i wlp4s0 -c 1,6,11            list the networks around
  wyrm watch -i wlp4s0 --monitor -d 120      watch a network for two minutes
  wyrm analyze capture.pcap                  audit a capture that was made elsewhere
  wyrm report capture.pcap -o report.html    write a shareable report
`)
}

// trimUsage keeps the help output tidy when embedded elsewhere.
func trimUsage(s string) string { return strings.TrimSpace(s) }
