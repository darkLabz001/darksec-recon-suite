// Package ports parses and normalizes port specifications.
//
// Supported syntax (a superset of the widely used nmap -p syntax):
//
//	80              single port
//	1-1024          inclusive range
//	80,443,8080     comma or whitespace separated list
//	T:80,443        force TCP
//	U:53,67         force UDP
//	-               every port (1-65535)
//
// A specification may also be read from a file with the "@path" prefix.
package ports

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rangeSep matches a range separator surrounded by optional whitespace so
// that specifications such as "10 - 12" behave like "10-12".
var rangeSep = regexp.MustCompile(`\s*-\s*`)

// Protocol identifies the transport a port list belongs to.
type Protocol string

const (
	// TCP is the default protocol for a bare port specification.
	TCP Protocol = "tcp"
	// UDP is selected with the "U:" prefix.
	UDP Protocol = "udp"
)

// Set holds deduplicated, sorted port lists keyed by protocol.
type Set struct {
	TCP []uint16
	UDP []uint16
}

// Empty reports whether the set contains no ports at all.
func (s Set) Empty() bool { return len(s.TCP) == 0 && len(s.UDP) == 0 }

// Count returns the total number of ports in the set.
func (s Set) Count() int { return len(s.TCP) + len(s.UDP) }

// For returns the port list for the given protocol.
func (s Set) For(p Protocol) []uint16 {
	if p == UDP {
		return s.UDP
	}
	return s.TCP
}

// Parse expands a port specification into a normalized Set.
func Parse(spec string) (Set, error) {
	var out Set
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return out, nil
	}
	spec = normalizeSpec(spec)

	tcp := make(map[uint16]struct{})
	udp := make(map[uint16]struct{})

	// A protocol prefix applies to the item that carries it and to every
	// item that follows it, until another prefix appears.
	proto := TCP

	for _, item := range splitItems(spec) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if len(item) > 1 && item[1] == ':' {
			switch strings.ToUpper(item[:1]) {
			case "T":
				proto = TCP
			case "U":
				proto = UDP
			default:
				return out, fmt.Errorf("invalid port protocol prefix %q", item[:1])
			}
			item = item[2:]
			if item == "" {
				// A bare protocol prefix selects the protocol only.
				continue
			}
		}

		if item == "-" {
			for p := 1; p <= 65535; p++ {
				if proto == UDP {
					udp[uint16(p)] = struct{}{}
				} else {
					tcp[uint16(p)] = struct{}{}
				}
			}
			continue
		}

		lo, hi, err := parseRange(item)
		if err != nil {
			return out, err
		}
		for p := int(lo); p <= int(hi); p++ {
			if proto == UDP {
				udp[uint16(p)] = struct{}{}
			} else {
				tcp[uint16(p)] = struct{}{}
			}
		}
	}

	out.TCP = sorted(tcp)
	out.UDP = sorted(udp)
	return out, nil
}

// ParseFile expands a port specification read from a file. Blank lines and
// lines beginning with '#' are ignored. Each remaining line is parsed as a
// full specification.
func ParseFile(path string) (Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return Set{}, err
	}
	defer f.Close()

	var out Set
	tcp := make(map[uint16]struct{})
	udp := make(map[uint16]struct{})

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := Parse(line)
		if err != nil {
			return Set{}, fmt.Errorf("%s: %w", path, err)
		}
		for _, p := range s.TCP {
			tcp[p] = struct{}{}
		}
		for _, p := range s.UDP {
			udp[p] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return Set{}, err
	}

	out.TCP = sorted(tcp)
	out.UDP = sorted(udp)
	return out, nil
}

// Full returns every valid TCP port.
func Full() []uint16 {
	p := make([]uint16, 65535)
	for i := range p {
		p[i] = uint16(i + 1)
	}
	return p
}

// Top returns the n most frequently used ports, ordered by descending
// popularity. The list is capped at the length of the bundled data set.
func Top(n int) []uint16 {
	if n <= 0 {
		return nil
	}
	if n > len(topPorts) {
		n = len(topPorts)
	}
	out := make([]uint16, n)
	copy(out, topPorts[:n])
	return out
}

// TopLen returns the number of ports in the bundled popularity list.
func TopLen() int { return len(topPorts) }

// TopUDP returns the n most frequently used UDP ports, ordered by
// descending popularity.
func TopUDP(n int) []uint16 {
	if n <= 0 {
		return nil
	}
	if n > len(topUDPPorts) {
		n = len(topUDPPorts)
	}
	out := make([]uint16, n)
	copy(out, topUDPPorts[:n])
	return out
}

// TopUDPLen returns the number of ports in the bundled UDP popularity list.
func TopUDPLen() int { return len(topUDPPorts) }

// Exclude removes every port in excl from list, returning a new slice.
// The result keeps the ordering of list.
func Exclude(list, excl []uint16) []uint16 {
	if len(excl) == 0 {
		return list
	}
	drop := make(map[uint16]struct{}, len(excl))
	for _, p := range excl {
		drop[p] = struct{}{}
	}
	out := make([]uint16, 0, len(list))
	for _, p := range list {
		if _, ok := drop[p]; !ok {
			out = append(out, p)
		}
	}
	return out
}

// Merge combines two sets, preserving sorted order.
func Merge(a, b Set) Set {
	tcp := append(append([]uint16{}, a.TCP...), b.TCP...)
	udp := append(append([]uint16{}, a.UDP...), b.UDP...)
	return Set{TCP: dedupe(tcp), UDP: dedupe(udp)}
}

func dedupe(in []uint16) []uint16 {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
	out := in[:1]
	for _, p := range in[1:] {
		if p != out[len(out)-1] {
			out = append(out, p)
		}
	}
	return out
}

func sorted(m map[uint16]struct{}) []uint16 {
	if len(m) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func splitItems(spec string) []string {
	return strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// normalizeSpec collapses whitespace around range separators so that
// "10 - 12" is treated as the range 10-12 rather than as three items.
func normalizeSpec(spec string) string {
	return rangeSep.ReplaceAllString(spec, "-")
}

func parseRange(s string) (uint16, uint16, error) {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, err := parsePort(strings.TrimSpace(s[:i]))
		if err != nil {
			return 0, 0, err
		}
		hi, err := parsePort(strings.TrimSpace(s[i+1:]))
		if err != nil {
			return 0, 0, err
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("invalid port range %q: start is greater than end", s)
		}
		return lo, hi, nil
	}
	p, err := parsePort(s)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", n)
	}
	return uint16(n), nil
}
