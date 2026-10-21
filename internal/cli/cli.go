// Package cli implements the command line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/detect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/engine"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/gui"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/output"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/stats"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/version"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// options holds the parsed command line.
type options struct {
	targets      stringList
	portSpec     string
	topPorts     int
	excludePorts string
	excludeCIDRs stringList
	resolve      bool
	maxHosts     int

	engine         string
	timeout        time.Duration
	concurrency    int
	minConcurrency int
	maxConcurrency int
	rate           float64
	sourceAddr     string
	iface          string
	order          string

	detect           bool
	noDetect         bool
	probeTimeout     time.Duration
	probes           string
	fallbacks        string
	ja3              bool
	favicon          bool
	userAgent        string
	hostHeader       string
	fingerprintRules string

	outputFile string
	format     string
	template   string
	noColor    bool
	showAll    bool
	quiet      bool
	stats      bool

	configFile string
	showHelp   bool
	showVer    bool
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// config is the JSON configuration file format.
type config struct {
	Timeout        *duration `json:"timeout"`
	Concurrency    *int      `json:"concurrency"`
	MinConcurrency *int      `json:"min_concurrency"`
	MaxConcurrency *int      `json:"max_concurrency"`
	Rate           *float64  `json:"rate"`
	Ports          *string   `json:"ports"`
	TopPorts       *int      `json:"top_ports"`
	ExcludePorts   *string   `json:"exclude_ports"`
	Engine         *string   `json:"engine"`
	Detect         *bool     `json:"detect"`
	UserAgent      *string   `json:"user_agent"`
	Format         *string   `json:"format"`
	Output         *string   `json:"output"`
	JA3            *bool     `json:"ja3"`
	Favicon        *bool     `json:"favicon"`
	ProbeTimeout   *duration `json:"probe_timeout"`
}

// duration is a time.Duration that accepts both a Go duration string, for
// example "3s", and a plain number of nanoseconds.
type duration struct {
	time.Duration
}

// UnmarshalJSON decodes a duration from a string or a number.
func (d *duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		d.Duration = v
		return nil
	}
	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("invalid duration %s", data)
	}
	d.Duration = time.Duration(n)
	return nil
}

// Run executes the command line interface and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	// The graphical interface is dispatched before the flag parser, because
	// it has a flag surface of its own.
	if len(args) > 0 && args[0] == "gui" {
		return gui.Run(args[1:], stdout, stderr)
	}

	opts := &options{}
	fs := flag.NewFlagSet("vantage", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var err error
	if err = parse(fs, opts, args, stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitUsage
		}
		fmt.Fprintf(stderr, "vantage: %v\n", err)
		return ExitUsage
	}
	if opts.showHelp {
		usage(stdout)
		return ExitOK
	}
	if opts.showVer {
		fmt.Fprintln(stdout, version.String())
		return ExitOK
	}

	if err := run(opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "vantage: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// parse builds the flag set and parses the command line.
func parse(fs *flag.FlagSet, opts *options, args []string, stdout io.Writer) error {
	fs.Usage = func() { usage(stderrOf(fs)) }

	fs.Var(&opts.targets, "targets", "target specification (repeatable, comma separated)")
	fs.Var(&opts.targets, "t", "target specification (shorthand)")
	fs.StringVar(&opts.portSpec, "ports", "", "port specification, for example 1-1024,443 or U:53")
	fs.StringVar(&opts.portSpec, "p", "", "port specification (shorthand)")
	fs.IntVar(&opts.topPorts, "top-ports", 0, "scan the N most common ports")
	fs.StringVar(&opts.excludePorts, "exclude-ports", "", "ports to exclude from the scan")
	fs.Var(&opts.excludeCIDRs, "exclude-cidr", "CIDR blocks to exclude (repeatable)")
	fs.BoolVar(&opts.resolve, "resolve", false, "allow hostnames as targets")
	fs.IntVar(&opts.maxHosts, "max-hosts", target.DefaultMaxHosts, "maximum addresses per target specification")

	fs.StringVar(&opts.engine, "engine", "connect", "scan engine: connect, syn or udp")
	fs.DurationVar(&opts.timeout, "timeout", engine.DefaultTimeout, "per probe timeout")
	fs.IntVar(&opts.concurrency, "concurrency", 0, "fixed number of concurrent probes (0 selects the adaptive controller)")
	fs.IntVar(&opts.minConcurrency, "min-concurrency", engine.DefaultMinConcurrency, "lower bound of the adaptive concurrency window")
	fs.IntVar(&opts.maxConcurrency, "max-concurrency", engine.DefaultMaxConcurrency, "upper bound of the adaptive concurrency window")
	fs.Float64Var(&opts.rate, "rate", 0, "maximum probes per second (0 means unlimited)")
	fs.StringVar(&opts.sourceAddr, "source-addr", "", "source address to bind the scanner to")
	fs.StringVar(&opts.iface, "interface", "", "network interface for the syn engine")
	fs.StringVar(&opts.order, "order", "auto", "probe order: host, port or auto")

	fs.BoolVar(&opts.detect, "detect-services", false, "identify services on open ports")
	fs.BoolVar(&opts.detect, "s", false, "identify services on open ports (shorthand)")
	fs.BoolVar(&opts.noDetect, "no-detect", false, "disable service detection")
	fs.DurationVar(&opts.probeTimeout, "probe-timeout", engine.DefaultDetectTimeout, "timeout for a single protocol probe")
	fs.StringVar(&opts.probes, "probe", "", "restrict detection to the named protocols")
	fs.StringVar(&opts.fallbacks, "fallback-probes", "http", "protocols tried on ports with no known mapping")
	fs.BoolVar(&opts.ja3, "ja3", false, "compute TLS handshake fingerprints")
	fs.BoolVar(&opts.favicon, "favicon", false, "collect favicon hashes for HTTP services")
	fs.StringVar(&opts.userAgent, "user-agent", "", "user agent sent with HTTP requests")
	fs.StringVar(&opts.hostHeader, "host-header", "", "host header sent with HTTP requests")
	fs.StringVar(&opts.fingerprintRules, "fingerprint-rules", "", "path to a JSON file with extra fingerprint rules")

	fs.StringVar(&opts.outputFile, "output", "", "write results to a file")
	fs.StringVar(&opts.outputFile, "o", "", "write results to a file (shorthand)")
	fs.StringVar(&opts.format, "format", "text", "output format: text, json, jsonl, csv, greppable or template")
	fs.StringVar(&opts.template, "template", "", "Go template used by the template format")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable coloured output")
	fs.BoolVar(&opts.showAll, "all", false, "include closed and filtered ports in the output")
	fs.BoolVar(&opts.quiet, "quiet", false, "suppress progress information")
	fs.BoolVar(&opts.stats, "stats", false, "show live progress statistics")

	fs.StringVar(&opts.configFile, "config", "", "path to a JSON configuration file")
	fs.BoolVar(&opts.showHelp, "help", false, "show this help message")
	fs.BoolVar(&opts.showHelp, "h", false, "show this help message (shorthand)")
	fs.BoolVar(&opts.showVer, "version", false, "print the version and exit")
	fs.BoolVar(&opts.showVer, "v", false, "print the version and exit (shorthand)")

	// A configuration file supplies defaults; command line flags override
	// it. The file is located before the main parse so that flags parsed
	// later take precedence.
	configPath := findConfigFlag(args)
	if configPath != "" {
		if err := applyConfig(opts, configPath); err != nil {
			return err
		}
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.showHelp || opts.showVer {
		return nil
	}

	// Positional arguments are treated as targets.
	if rest := fs.Args(); len(rest) > 0 {
		for _, arg := range rest {
			if err := opts.targets.Set(arg); err != nil {
				return err
			}
		}
	}
	return nil
}

func stderrOf(fs *flag.FlagSet) io.Writer {
	if fs.Output() != nil {
		return fs.Output()
	}
	return os.Stderr
}

// findConfigFlag locates the --config flag before the real parse.
func findConfigFlag(args []string) string {
	for i, arg := range args {
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimPrefix(arg, "-config=")
		}
	}
	return ""
}

// applyConfig loads a JSON configuration file into the options.
func applyConfig(opts *options, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	if cfg.Timeout != nil {
		opts.timeout = cfg.Timeout.Duration
	}
	if cfg.Concurrency != nil {
		opts.concurrency = *cfg.Concurrency
	}
	if cfg.MinConcurrency != nil {
		opts.minConcurrency = *cfg.MinConcurrency
	}
	if cfg.MaxConcurrency != nil {
		opts.maxConcurrency = *cfg.MaxConcurrency
	}
	if cfg.Rate != nil {
		opts.rate = *cfg.Rate
	}
	if cfg.Ports != nil {
		opts.portSpec = *cfg.Ports
	}
	if cfg.TopPorts != nil {
		opts.topPorts = *cfg.TopPorts
	}
	if cfg.ExcludePorts != nil {
		opts.excludePorts = *cfg.ExcludePorts
	}
	if cfg.Engine != nil {
		opts.engine = *cfg.Engine
	}
	if cfg.Detect != nil {
		opts.detect = *cfg.Detect
	}
	if cfg.UserAgent != nil {
		opts.userAgent = *cfg.UserAgent
	}
	if cfg.Format != nil {
		opts.format = *cfg.Format
	}
	if cfg.Output != nil {
		opts.outputFile = *cfg.Output
	}
	if cfg.JA3 != nil {
		opts.ja3 = *cfg.JA3
	}
	if cfg.Favicon != nil {
		opts.favicon = *cfg.Favicon
	}
	if cfg.ProbeTimeout != nil {
		opts.probeTimeout = cfg.ProbeTimeout.Duration
	}
	return nil
}

// run performs the scan.
func run(opts *options, stdout, stderr io.Writer) error {
	if len(opts.targets) == 0 {
		usage(stderr)
		return errors.New("no targets specified")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	exclusions, err := target.ParseExclusions(opts.excludeCIDRs)
	if err != nil {
		return err
	}

	hosts, err := target.Parse(ctx, opts.targets, target.Options{
		MaxHosts:         opts.maxHosts,
		ResolveHostnames: opts.resolve,
		ExcludeCIDRs:     exclusions,
	})
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("no targets resolved")
	}

	portSet, err := buildPortSet(opts)
	if err != nil {
		return err
	}

	engineCfg, err := buildEngineConfig(opts)
	if err != nil {
		return err
	}

	outWriter := stdout
	if opts.outputFile != "" {
		f, err := os.Create(opts.outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		outWriter = f
	}

	writer, err := output.New(output.Options{
		Format:   output.Format(opts.format),
		Output:   outWriter,
		Template: opts.template,
		NoColor:  opts.noColor || opts.outputFile != "",
		ShowAll:  opts.showAll,
	})
	if err != nil {
		return err
	}

	reporter := stats.New(stderr, opts.quiet || !opts.stats)
	reporter.SetTotal(int64(len(hosts)) * int64(portSet.Count()))

	results := make(chan engine.Result, 1024)
	done := make(chan struct{})

	var scanErr error
	go func() {
		defer close(done)
		scanErr = scan(ctx, opts, engineCfg, hosts, portSet, results)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for res := range results {
			if err := writer.Write(res); err != nil {
				fmt.Fprintf(stderr, "vantage: writing results: %v\n", err)
				continue
			}
			reporter.Add(string(res.State))
		}
	}()

	reporter.Start(done)
	<-done
	close(results)
	// The writer must not be flushed before every result has been
	// rendered, otherwise the tail of a scan is lost.
	wg.Wait()

	if err := writer.Close(); err != nil {
		return err
	}
	reporter.Summary()
	return scanErr
}

// scan dispatches to the requested engine.
func scan(ctx context.Context, opts *options, cfg engine.Config, hosts []target.Host, portSet ports.Set, out chan<- engine.Result) error {
	switch strings.ToLower(opts.engine) {
	case "", "connect", "tcp", "tcp-connect":
		s := engine.NewConnectScanner(cfg)
		return s.Scan(ctx, hosts, portSet.TCP, out)
	case "syn", "tcp-syn":
		s, err := engine.NewSYNScanner(cfg)
		if err != nil {
			return err
		}
		return s.Scan(ctx, hosts, portSet.TCP, out)
	case "udp":
		s, err := engine.NewUDPScanner(cfg)
		if err != nil {
			return err
		}
		return s.Scan(ctx, hosts, portSet.UDP, out)
	default:
		return fmt.Errorf("unknown engine %q", opts.engine)
	}
}

// buildPortSet resolves the port specification into a concrete port set.
func buildPortSet(opts *options) (ports.Set, error) {
	var set ports.Set
	var err error

	udp := isUDPEngine(opts.engine)

	switch {
	case opts.topPorts > 0:
		if udp {
			if opts.topPorts > ports.TopUDPLen() {
				return set, fmt.Errorf("the bundled popularity list only covers %d UDP ports", ports.TopUDPLen())
			}
			set.UDP = ports.TopUDP(opts.topPorts)
			break
		}
		if opts.topPorts > ports.TopLen() {
			return set, fmt.Errorf("the bundled popularity list only covers %d ports", ports.TopLen())
		}
		set.TCP = ports.Top(opts.topPorts)
	case strings.TrimSpace(opts.portSpec) != "":
		set, err = ports.Parse(opts.portSpec)
		if err != nil {
			return set, err
		}
		// A bare port specification in the UDP engine means a UDP port.
		if udp && !specHasProtocolPrefix(opts.portSpec) {
			set.UDP = set.TCP
			set.TCP = nil
		}
	default:
		if udp {
			set.UDP = ports.TopUDP(50)
		} else {
			set.TCP = ports.Top(1000)
		}
	}

	if strings.TrimSpace(opts.excludePorts) != "" {
		excl, err := ports.Parse(opts.excludePorts)
		if err != nil {
			return set, err
		}
		set.TCP = ports.Exclude(set.TCP, excl.TCP)
		set.UDP = ports.Exclude(set.UDP, excl.UDP)
	}

	if set.Empty() {
		return set, errors.New("no ports selected")
	}
	return set, nil
}

// isUDPEngine reports whether the engine scans UDP.
func isUDPEngine(name string) bool {
	switch strings.ToLower(name) {
	case "udp":
		return true
	}
	return false
}

// specHasProtocolPrefix reports whether the specification names a protocol
// explicitly, for example "T:80" or "U:53".
func specHasProtocolPrefix(spec string) bool {
	for _, item := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		item = strings.TrimSpace(item)
		if len(item) > 1 && item[1] == ':' {
			return true
		}
	}
	return false
}

// buildEngineConfig converts the command line into an engine configuration.
func buildEngineConfig(opts *options) (engine.Config, error) {
	cfg := engine.Config{
		Timeout:        opts.timeout,
		Concurrency:    opts.concurrency,
		MinConcurrency: opts.minConcurrency,
		MaxConcurrency: opts.maxConcurrency,
		Rate:           opts.rate,
		Detect:         opts.detect && !opts.noDetect,
		DetectTimeout:  opts.probeTimeout,
		UserAgent:      opts.userAgent,
		EnableJA3:      opts.ja3,
		EnableHTTP:     true,
		EnableFavicon:  opts.favicon,
		HostHeader:     opts.hostHeader,
		Interface:      opts.iface,
	}

	switch strings.ToLower(opts.order) {
	case "host":
		cfg.Order = engine.OrderHost
	case "port":
		cfg.Order = engine.OrderPort
	case "", "auto":
		cfg.Order = engine.OrderAuto
	default:
		return cfg, fmt.Errorf("unknown order %q", opts.order)
	}

	if opts.sourceAddr != "" {
		addr, err := netip.ParseAddr(opts.sourceAddr)
		if err != nil {
			return cfg, fmt.Errorf("invalid source address %q: %w", opts.sourceAddr, err)
		}
		cfg.SourceAddr = addr.Unmap()
	}

	if opts.probes != "" {
		for _, name := range strings.Split(opts.probes, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.Protocols = append(cfg.Protocols, name)
			}
		}
	}

	if opts.fallbacks != "" {
		for _, name := range strings.Split(opts.fallbacks, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.Fallbacks = append(cfg.Fallbacks, name)
			}
		}
	}

	if opts.fingerprintRules != "" {
		rules, err := detect.LoadRules(opts.fingerprintRules)
		if err != nil {
			return cfg, err
		}
		cfg.Rules = rules
	}

	return cfg, nil
}
