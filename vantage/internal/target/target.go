// Package target expands user supplied target specifications into concrete
// host lists ready for scanning.
//
// Supported syntax:
//
//	192.168.1.1            single address
//	192.168.1.0/24         CIDR block
//	192.168.1.1-192.168.1.50   inclusive range
//	192.168.1.1-50         range with an implicit prefix
//	192.168.1.*            wildcard, equivalent to a /24
//	example.com            hostname (resolved to A and AAAA records)
//	@hosts.txt              read targets from a file, one per line
//	-                       read targets from stdin
package target

import (
	"bufio"
	"context"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Host represents a single scan target, which may have both an IPv4 and an
// IPv6 address. When both are present the engine races them using the
// Happy Eyeballs algorithm.
type Host struct {
	V4 netip.Addr
	V6 netip.Addr
}

// Addrs returns the non-empty addresses of the host, preferring IPv6.
func (h Host) Addrs() []netip.Addr {
	switch {
	case h.V6.IsValid() && h.V4.IsValid():
		return []netip.Addr{h.V6, h.V4}
	case h.V6.IsValid():
		return []netip.Addr{h.V6}
	case h.V4.IsValid():
		return []netip.Addr{h.V4}
	default:
		return nil
	}
}

// Any returns one representative address for the host.
func (h Host) Any() netip.Addr {
	if h.V4.IsValid() {
		return h.V4
	}
	return h.V6
}

// Options controls target expansion.
type Options struct {
	// MaxHosts caps the total number of addresses produced by a single
	// specification. Zero means the package default.
	MaxHosts int
	// ResolveHostnames enables DNS resolution of non-IP targets.
	ResolveHostnames bool
	// IncludeNetworkAndBroadcast keeps the first and last address of an
	// IPv4 CIDR block instead of discarding them.
	IncludeNetworkAndBroadcast bool
	// ExcludeCIDRs removes matching addresses from the final result.
	ExcludeCIDRs []netip.Prefix
}

// DefaultMaxHosts is the default cap on addresses produced per specification.
const DefaultMaxHosts = 1 << 20

// Parse expands the given specifications into a list of hosts.
//
// A specification beginning with '@' is read from the named file; the
// special name '-' reads from standard input. Each file line may itself
// contain a comma separated list of specifications.
func Parse(ctx context.Context, specs []string, opts Options) ([]Host, error) {
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = DefaultMaxHosts
	}

	var hosts []Host
	for _, spec := range specs {
		expanded, err := parseOne(ctx, spec, opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec, err)
		}
		hosts = append(hosts, expanded...)
	}

	hosts = dedupe(hosts)
	hosts = applyExclusions(hosts, opts.ExcludeCIDRs)
	return hosts, nil
}

func parseOne(ctx context.Context, spec string, opts Options) ([]Host, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	if spec == "-" {
		return readTargets(ctx, os.Stdin, opts)
	}
	if strings.HasPrefix(spec, "@") {
		path := strings.TrimPrefix(spec, "@")
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readTargets(ctx, f, opts)
	}

	// A single specification may hold a comma separated list.
	if strings.Contains(spec, ",") {
		var out []Host
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			h, err := parseOne(ctx, part, opts)
			if err != nil {
				return nil, err
			}
			out = append(out, h...)
		}
		return out, nil
	}

	if strings.Contains(spec, "*") {
		return parseWildcard(spec, opts)
	}
	if strings.Contains(spec, "/") {
		return parseCIDR(spec, opts)
	}
	if strings.Contains(spec, "-") {
		return parseRange(spec, opts)
	}
	if addr, err := netip.ParseAddr(spec); err == nil {
		return []Host{hostFrom(addr)}, nil
	}
	if opts.ResolveHostnames {
		return resolveHost(ctx, spec)
	}
	return nil, fmt.Errorf("not a valid IP address or CIDR (pass --resolve to allow hostnames)")
}

func parseCIDR(spec string, opts Options) ([]Host, error) {
	pfx, err := netip.ParsePrefix(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	return expandPrefix(pfx, opts)
}

func expandPrefix(pfx netip.Prefix, opts Options) ([]Host, error) {
	pfx = pfx.Masked()
	bits := pfx.Bits()
	total := uint64(1) << uint(pfx.Addr().BitLen()-bits)
	if total > uint64(opts.MaxHosts) {
		return nil, fmt.Errorf("prefix expands to %d addresses, exceeding the limit of %d (raise --max-hosts or narrow the range)", total, opts.MaxHosts)
	}

	out := make([]Host, 0, total)
	addr := pfx.Addr()
	skipEdges := pfx.Addr().Is4() && !opts.IncludeNetworkAndBroadcast && total > 2
	for i := uint64(0); i < total; i++ {
		a := addr
		next := addr.Next()
		if !next.IsValid() {
			break
		}
		addr = next
		if skipEdges && (i == 0 || i == total-1) {
			continue
		}
		out = append(out, hostFrom(a))
	}
	return out, nil
}

func parseWildcard(spec string, opts Options) ([]Host, error) {
	parts := strings.Split(spec, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("wildcard must have four octets")
	}
	for i, p := range parts {
		if p != "*" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("invalid octet %q", p)
			}
			continue
		}
		// Everything after the wildcard must also be a wildcard.
		for _, q := range parts[i+1:] {
			if q != "*" {
				return nil, fmt.Errorf("everything after the wildcard must be a wildcard")
			}
		}
		// The wildcard octets become zeroes to form the base address.
		base := make([]string, len(parts))
		copy(base, parts)
		for j := i; j < len(base); j++ {
			base[j] = "0"
		}
		prefix := i * 8
		return expandPrefix(netip.PrefixFrom(netip.MustParseAddr(strings.Join(base, ".")), prefix), opts)
	}
	return nil, fmt.Errorf("invalid wildcard %q", spec)
}

func parseRange(spec string, opts Options) ([]Host, error) {
	lo, hi, err := splitRange(spec)
	if err != nil {
		return nil, err
	}

	loAddr, err := netip.ParseAddr(lo)
	if err != nil {
		return nil, fmt.Errorf("invalid range start %q", lo)
	}
	hiAddr, err := netip.ParseAddr(hi)
	if err != nil {
		return nil, fmt.Errorf("invalid range end %q", hi)
	}
	if loAddr.Is4() != hiAddr.Is4() {
		return nil, fmt.Errorf("range mixes address families")
	}
	if loAddr.Compare(hiAddr) > 0 {
		return nil, fmt.Errorf("range start is greater than range end")
	}

	count, overflow := addrRangeLen(loAddr, hiAddr)
	if overflow || count > uint64(opts.MaxHosts) {
		return nil, fmt.Errorf("range spans %d addresses, exceeding the limit of %d", count, opts.MaxHosts)
	}

	out := make([]Host, 0, count)
	a := loAddr
	for {
		out = append(out, hostFrom(a))
		if a == hiAddr {
			break
		}
		next := a.Next()
		if !next.IsValid() {
			break
		}
		a = next
	}
	return out, nil
}

// splitRange accepts both "a.b.c.d-e.f.g.h" and "a.b.c.d-e".
func splitRange(spec string) (string, string, error) {
	idx := strings.LastIndex(spec, "-")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid range %q", spec)
	}
	lo := strings.TrimSpace(spec[:idx])
	hi := strings.TrimSpace(spec[idx+1:])

	loOctets := strings.Split(lo, ".")
	if hiOctets := strings.Split(hi, "."); len(hiOctets) == 1 {
		// Shorthand: replace the final octet.
		if len(loOctets) != 4 {
			return "", "", fmt.Errorf("invalid range start %q", lo)
		}
		n, err := strconv.Atoi(hi)
		if err != nil || n < 0 || n > 255 {
			return "", "", fmt.Errorf("invalid range end %q", hi)
		}
		hi = strings.Join(append(append([]string{}, loOctets[:3]...), strconv.Itoa(n)), ".")
	}
	if _, err := netip.ParseAddr(hi); err != nil {
		return "", "", fmt.Errorf("invalid range end %q", hi)
	}
	return lo, hi, nil
}

func addrRangeLen(lo, hi netip.Addr) (uint64, bool) {
	if lo.Is4() != hi.Is4() {
		return 0, true
	}
	if lo.Is4() {
		lb, hb := lo.As4(), hi.As4()
		l := uint64(lb[0])<<24 | uint64(lb[1])<<16 | uint64(lb[2])<<8 | uint64(lb[3])
		h := uint64(hb[0])<<24 | uint64(hb[1])<<16 | uint64(hb[2])<<8 | uint64(hb[3])
		return h - l + 1, false
	}
	lb, hb := lo.As16(), hi.As16()
	var l, h big.Int
	l.SetBytes(lb[:])
	h.SetBytes(hb[:])
	if h.Cmp(&l) < 0 {
		return 0, true
	}
	diff := new(big.Int).Sub(&h, &l)
	if !diff.IsUint64() {
		return 0, true
	}
	return diff.Uint64() + 1, false
}

func resolveHost(ctx context.Context, name string) ([]Host, error) {
	r := &net.Resolver{}
	ips, err := r.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", name, err)
	}
	var host Host
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() && !host.V4.IsValid() {
			host.V4 = ip
		} else if ip.Is6() && !host.V6.IsValid() {
			host.V6 = ip
		}
	}
	if !host.V4.IsValid() && !host.V6.IsValid() {
		return nil, fmt.Errorf("%q resolved to no addresses", name)
	}
	return []Host{host}, nil
}

func readTargets(ctx context.Context, r interface {
	Read([]byte) (int, error)
}, opts Options) ([]Host, error) {
	var out []Host
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, err := parseOne(ctx, line, opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", line, err)
		}
		out = append(out, h...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func hostFrom(a netip.Addr) Host {
	a = a.Unmap()
	if a.Is4() {
		return Host{V4: a}
	}
	return Host{V6: a}
}

func dedupe(in []Host) []Host {
	seen := make(map[netip.Addr]struct{}, len(in))
	out := in[:0]
	for _, h := range in {
		key := h.Any()
		if key.IsValid() {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
		}
		out = append(out, h)
	}
	return out
}

func applyExclusions(hosts []Host, excl []netip.Prefix) []Host {
	if len(excl) == 0 {
		return hosts
	}
	out := hosts[:0]
	for _, h := range hosts {
		excluded := false
		for _, p := range excl {
			if h.V4.IsValid() && p.Addr().Is4() && p.Contains(h.V4) {
				excluded = true
				break
			}
			if h.V6.IsValid() && p.Addr().Is6() && p.Contains(h.V6) {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, h)
		}
	}
	return out
}

// ParseExclusions parses exclusion prefixes such as "10.0.0.0/8".
func ParseExclusions(specs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range specs {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid exclusion prefix %q: %w", part, err)
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}
