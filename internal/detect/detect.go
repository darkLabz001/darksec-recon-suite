// Package detect identifies the service running behind an open port.
//
// Detection has two layers. The first is protocol probing: a small request
// is exchanged with the service using the protocol it is expected to speak.
// The second is fingerprinting: regular expressions are applied to the
// banner to extract product names and versions.
package detect

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/proto"
)

// ServiceInfo holds everything learned about an open port.
type ServiceInfo struct {
	// Service is the canonical service name, for example "http".
	Service string
	// Product is the software implementation, for example "nginx".
	Product string
	// Version is the detected version.
	Version string
	// Extra carries vendor, build or banner details.
	Extra string
	// CPE is the Common Platform Enumeration identifier.
	CPE string
	// Banner is the raw greeting, trimmed.
	Banner string
	// Confidence is the detector's confidence in the result, from 0 to 1.
	Confidence float64
	// Method records how the service was identified.
	Method string
	// JA3 is the MD5 fingerprint of the ClientHello sent by the scanner.
	JA3 string
	// JA3S is the MD5 fingerprint of the ServerHello received.
	JA3S string
	// Favicon is the favicon fingerprint of an HTTP service.
	Favicon string
	// TLS holds details of the TLS handshake.
	TLS *proto.TLSInfo
	// HTTP holds details of the HTTP response.
	HTTP *proto.HTTPInfo
	// RawText is the untrimmed banner text.
	RawText string
}

// Empty reports whether nothing was identified.
func (s *ServiceInfo) Empty() bool {
	return s == nil || (s.Service == "" && s.Product == "")
}

// Config configures the detector.
type Config struct {
	// Timeout bounds each individual protocol exchange.
	Timeout time.Duration
	// UserAgent is sent with HTTP requests.
	UserAgent string
	// EnableJA3 turns on TLS handshake fingerprinting.
	EnableJA3 bool
	// EnableHTTP allows HTTP probing to run.
	EnableHTTP bool
	// EnableFavicon allows favicon hash collection.
	EnableFavicon bool
	// HostHeader overrides the Host header used for HTTP requests.
	HostHeader string
	// Protocols restricts detection to the named protocols.
	Protocols []string
	// Fallbacks are the protocols tried on ports that have no known
	// protocol mapping. When empty, HTTP is used.
	Fallbacks []string
	// Rules are additional fingerprint rules.
	Rules []Rule
	// BannerTimeout bounds the generic banner read.
	BannerTimeout time.Duration
}

// Detector identifies services on open ports.
type Detector struct {
	cfg   Config
	rules []Rule
}

// New returns a detector ready for use.
func New(cfg Config) *Detector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.BannerTimeout <= 0 {
		cfg.BannerTimeout = 2 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = proto.DefaultUserAgent
	}
	return &Detector{cfg: cfg, rules: Rules(cfg.Rules)}
}

// Detect inspects an established connection and identifies the service.
//
// The redial callback is used to obtain a fresh connection when a protocol
// probe fails and another candidate, or the generic banner read, still has
// to be attempted.
func (d *Detector) Detect(ctx context.Context, ap netip.AddrPort, conn net.Conn, redial func(context.Context) (net.Conn, error)) *ServiceInfo {
	if conn == nil {
		return nil
	}
	current := conn

	// The connection may be replaced by a redialed one during detection,
	// so close whatever is current when the function returns.
	defer func() {
		if current != nil {
			current.Close()
		}
	}()

	opts := proto.Options{
		Timeout:       d.cfg.Timeout,
		UserAgent:     d.cfg.UserAgent,
		EnableJA3:     d.cfg.EnableJA3,
		EnableHTTP:    d.cfg.EnableHTTP,
		EnableFavicon: d.cfg.EnableFavicon,
		HostHeader:    d.cfg.HostHeader,
	}

	candidates := d.candidates(ap.Port())

	for i, name := range candidates {
		prober, ok := proto.Lookup(name)
		if !ok {
			continue
		}
		if !d.cfg.EnableHTTP && (name == "http" || name == "https") {
			continue
		}

		obs, err := prober.Probe(ctx, current, ap, opts)
		if err != nil {
			if i+1 < len(candidates) && redial != nil {
				if fresh, rerr := redial(ctx); rerr == nil {
					current.Close()
					current = fresh
				}
			}
			continue
		}
		info := d.build(obs)
		if info != nil {
			d.collectFavicon(ctx, ap, info)
		}
		return info
	}

	// No protocol probe produced a result. Fall back to reading whatever
	// the service greets us with.
	if redial != nil {
		if fresh, err := redial(ctx); err == nil {
			current.Close()
			current = fresh
		}
	}
	banner, err := d.readBanner(current)
	if err != nil && len(banner) == 0 {
		return nil
	}
	info := &ServiceInfo{
		Banner:  sanitizeBanner(banner),
		Method:  "banner",
		RawText: string(banner),
	}
	d.applyRules(string(banner), info)
	if info.Service == "" && info.Product == "" {
		return nil
	}
	info.Confidence = 0.6
	return info
}

// Fingerprint applies the fingerprint database to a raw banner.
//
// It is used for protocols that do not fit the connection oriented detection
// flow, such as UDP services that answer with a single datagram.
func (d *Detector) Fingerprint(banner string) *ServiceInfo {
	if banner == "" {
		return nil
	}
	info := &ServiceInfo{
		Method:     "fingerprint",
		Confidence: 0.6,
	}
	d.applyRules(banner, info)
	if info.Service == "" && info.Product == "" {
		return nil
	}
	if info.Service == "" {
		info.Service = "unknown"
	}
	if info.Version != "" {
		info.Confidence = 1.0
	}
	return info
}

// candidates returns the protocol names to try for a port.
func (d *Detector) candidates(port uint16) []string {
	if len(d.cfg.Protocols) > 0 {
		return d.cfg.Protocols
	}
	if list := proto.Candidates(port); len(list) > 0 {
		// Only the protocols that have a prober can be tried. The rest
		// would merely waste a connection.
		usable := make([]string, 0, len(list))
		for _, name := range list {
			if _, ok := proto.Lookup(name); ok {
				usable = append(usable, name)
			}
		}
		if len(usable) > 0 {
			return usable
		}
	}
	// The port has no known mapping, so the universal protocols are tried
	// instead. This is what lets the scanner identify a service that runs
	// on an unusual port.
	return d.fallbacks()
}

// fallbacks returns the universal protocol list.
func (d *Detector) fallbacks() []string {
	if len(d.cfg.Fallbacks) > 0 {
		return d.cfg.Fallbacks
	}
	return []string{"http"}
}

// readBanner performs a short read for a generic greeting.
func (d *Detector) readBanner(conn net.Conn) ([]byte, error) {
	if conn == nil {
		return nil, nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.BannerTimeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if n <= 0 {
		return nil, err
	}
	return buf[:n], nil
}

// build converts a protocol observation into a service description.
func (d *Detector) build(obs *proto.Observation) *ServiceInfo {
	info := &ServiceInfo{
		Service:    obs.Service,
		Product:    obs.Product,
		Version:    obs.Version,
		Extra:      obs.Extra,
		Banner:     sanitizeBanner([]byte(obs.Banner)),
		Method:     "probe",
		JA3:        obs.JA3,
		JA3S:       obs.JA3S,
		TLS:        obs.TLS,
		HTTP:       obs.HTTP,
		Confidence: 0.9,
		RawText:    string(obs.Raw),
	}

	if info.Service == "" {
		info.Service = "unknown"
	}
	if info.Version != "" {
		info.Confidence = 1.0
	}

	// Fingerprint the banner to enrich or correct the probe result.
	if len(obs.Raw) > 0 {
		d.applyRules(string(obs.Raw), info)
	}
	if info.CPE == "" && info.Product != "" && info.Version != "" {
		info.CPE = genericCPE(info.Product, info.Version)
	}
	return info
}

// applyRules runs the fingerprint database over a banner.
func (d *Detector) applyRules(banner string, info *ServiceInfo) {
	if banner == "" {
		return
	}
	for _, rule := range d.rules {
		probe := *info
		if !rule.Match(banner, &probe) {
			continue
		}
		if probe.Product != "" {
			info.Product = probe.Product
		}
		if probe.Version != "" {
			info.Version = probe.Version
		}
		if probe.CPE != "" {
			info.CPE = probe.CPE
		}
		if info.Service == "" || info.Service == "unknown" {
			info.Service = rule.Service
		}
		return
	}
}

// collectFavicon fetches the favicon of an HTTP service.
func (d *Detector) collectFavicon(ctx context.Context, ap netip.AddrPort, info *ServiceInfo) {
	if !d.cfg.EnableFavicon || info == nil || info.HTTP == nil {
		return
	}
	conn, err := net.DialTimeout("tcp", ap.String(), d.cfg.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	host := d.cfg.HostHeader
	if host == "" {
		host = ap.Addr().Unmap().String()
	}
	if hash := fetchFavicon(conn, host, d.cfg.UserAgent, d.cfg.Timeout); hash != "" {
		info.Favicon = hash
	}
}

// sanitizeBanner trims a banner to a sensible length for display.
func sanitizeBanner(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	const limit = 512
	text := string(raw)
	if len(text) > limit {
		text = text[:limit] + "..."
	}
	return strings.TrimSpace(text)
}

// genericCPE builds a best effort CPE identifier from a product name.
func genericCPE(product, version string) string {
	vendor := strings.ToLower(strings.TrimSpace(product))
	vendor = strings.ReplaceAll(vendor, " ", "_")
	vendor = strings.ReplaceAll(vendor, "-", "_")
	if vendor == "" {
		return ""
	}
	return "cpe:2.3:a:" + vendor + ":" + vendor + ":" + version + ":*:*:*:*:*:*:*"
}
