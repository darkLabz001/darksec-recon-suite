package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/version"
)

// usage prints the help message.
func usage(w io.Writer) {
	fmt.Fprintf(w, `vantage %s - a fast, precise port scanner

Usage:
  vantage [flags] <target>...
  vantage -p 1-1024 192.168.1.0/24
  vantage -s --ja3 -p 443,8443 example.com

Targets:
  A target is an IP address, a CIDR block, an address range, a wildcard
  block or a hostname. Use "@file" to read targets from a file and "-" to
  read them from standard input.

    192.168.1.1              single address
    192.168.1.0/24           CIDR block
    192.168.1.10-192.168.1.60  address range
    192.168.1.*              wildcard block
    example.com              hostname (requires --resolve)

Flags:
`, version.Version)

	type flagLine struct {
		name string
		desc string
	}
	lines := []flagLine{
		{"-t, --targets", "target specification (repeatable, comma separated)"},
		{"-p, --ports", "port specification, for example 1-1024,443 or U:53"},
		{"    --top-ports", "scan the N most common ports (the bundled list covers " + itoa(ports.TopLen()) + ")"},
		{"    --exclude-ports", "ports to skip"},
		{"    --exclude-cidr", "CIDR blocks to skip (repeatable)"},
		{"    --resolve", "allow hostnames as targets"},
		{"    --max-hosts", "maximum addresses produced by one target specification"},
		{"", ""},
		{"    --engine", "scan engine: connect, syn or udp"},
		{"    --timeout", "per probe timeout"},
		{"    --concurrency", "fixed concurrency (0 selects the adaptive controller)"},
		{"    --min-concurrency", "lower bound of the adaptive concurrency window"},
		{"    --max-concurrency", "upper bound of the adaptive concurrency window"},
		{"    --rate", "maximum probes per second (0 means unlimited)"},
		{"    --source-addr", "source address to bind the scanner to"},
		{"    --interface", "network interface used by the syn engine"},
		{"    --order", "probe order: host, port or auto"},
		{"", ""},
		{"-s, --detect-services", "identify services on open ports"},
		{"    --no-detect", "disable service detection"},
		{"    --probe-timeout", "timeout for a single protocol probe"},
		{"    --probe", "restrict detection to the named protocols"},
		{"    --ja3", "compute TLS handshake fingerprints"},
		{"    --favicon", "collect favicon hashes for HTTP services"},
		{"    --user-agent", "user agent sent with HTTP requests"},
		{"    --host-header", "host header sent with HTTP requests"},
		{"    --fingerprint-rules", "JSON file with extra fingerprint rules"},
		{"", ""},
		{"-o, --output", "write results to a file"},
		{"    --format", "output format: text, json, jsonl, csv, greppable or template"},
		{"    --template", "Go template used by the template format"},
		{"    --no-color", "disable coloured output"},
		{"    --all", "include closed and filtered ports"},
		{"    --quiet", "suppress progress information"},
		{"    --stats", "show live progress statistics"},
		{"", ""},
		{"    --config", "JSON configuration file with defaults"},
		{"-v, --version", "print the version and exit"},
		{"-h, --help", "print this help and exit"},
	}

	for _, l := range lines {
		if l.name == "" {
			fmt.Fprintln(w)
			continue
		}
		fmt.Fprintf(w, "  %-22s %s\n", l.name, l.desc)
	}

	fmt.Fprint(w, `
Examples:
  vantage 192.168.1.0/24                       scan the most common ports
  vantage -p 1-65535 --rate 5000 10.0.0.0/8   full sweep, rate limited
  vantage -s --ja3 -p 443,8443 host.example   detect services and TLS fingerprints
  vantage --engine syn -p 1-1024 10.0.0.1     half open scan (needs CAP_NET_RAW)
  vantage --format jsonl -o scan.jsonl host   machine readable output
`)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// trimUsage keeps the help output tidy when embedded elsewhere.
func trimUsage(s string) string { return strings.TrimSpace(s) }
