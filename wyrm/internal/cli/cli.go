// Package cli implements the command line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/capture"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/gui"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/pcap"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/report"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/version"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// options holds the flags that every subcommand shares.
type options struct {
	iface        string
	channels     string
	hop          bool
	hopInterval  time.Duration
	monitor      bool
	filter       string
	output       string
	format       string
	duration     time.Duration
	sudoPassword string
	noColor      bool
	quiet        bool
	showHelp     bool
	showVer      bool
}

// Run executes the command line interface and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return ExitUsage
	}

	switch args[0] {
	case "gui":
		return gui.Run(args[1:], stdout, stderr)
	case "survey":
		return runSurvey(args[1:], stdout, stderr)
	case "watch":
		return runWatch(args[1:], stdout, stderr)
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "iface":
		return runIface(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.String())
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	}

	// A bare path is a convenience for the analyze subcommand.
	if strings.HasSuffix(args[0], ".pcap") || strings.HasSuffix(args[0], ".pcapng") {
		return runAnalyze(args, stdout, stderr)
	}

	fmt.Fprintf(stderr, "wyrm: unknown command %q\n", args[0])
	usage(stderr)
	return ExitUsage
}

// newFlagSet builds the flag set of a subcommand.
func newFlagSet(name string, opts *options, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("wyrm "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&opts.iface, "interface", "", "wireless interface to use")
	fs.StringVar(&opts.iface, "i", "", "wireless interface to use (shorthand)")
	fs.StringVar(&opts.channels, "channels", "", "channels to use, for example 1,6,11 or 36-48")
	fs.StringVar(&opts.channels, "c", "", "channels to use (shorthand)")
	fs.BoolVar(&opts.hop, "hop", true, "hop over the channels")
	fs.DurationVar(&opts.hopInterval, "hop-interval", 250*time.Millisecond, "time on each channel")
	fs.BoolVar(&opts.monitor, "monitor", false, "switch the interface to monitor mode")
	fs.StringVar(&opts.filter, "filter", "", "packet filter, for example \"type mgt\"")
	fs.StringVar(&opts.output, "output", "", "file to write the capture or the report to")
	fs.StringVar(&opts.output, "o", "", "file to write the capture or the report to (shorthand)")
	fs.StringVar(&opts.format, "format", "text", "output format: text, json or html (default: from the extension)")
	fs.DurationVar(&opts.duration, "duration", 0, "length of the capture (0 means until it is stopped)")
	fs.StringVar(&opts.sudoPassword, "sudo-password", os.Getenv("WYRM_SUDO_PASSWORD"), "password used to run the capture through sudo")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable coloured output")
	fs.BoolVar(&opts.quiet, "quiet", false, "suppress progress information")
	fs.BoolVar(&opts.showHelp, "help", false, "show the help message")
	fs.BoolVar(&opts.showHelp, "h", false, "show the help message (shorthand)")
	fs.BoolVar(&opts.showVer, "version", false, "print the version and exit")
	fs.BoolVar(&opts.showVer, "v", false, "print the version and exit (shorthand)")
	return fs
}

// parse reads the flags of a subcommand and returns the arguments that are
// not flags.
//
// The flag package stops reading at the first argument that is not a flag, so
// a flag that follows the file name would be ignored.  The leftovers are
// therefore read in a second pass, which lets the flags be written either
// way round.
func parse(fs *flag.FlagSet, opts *options, args []string, stdout io.Writer) ([]string, error) {
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	positional := fs.Args()
	if len(positional) > 1 {
		if err := fs.Parse(positional[1:]); err != nil {
			return nil, err
		}
		positional = positional[:1]
	}
	if opts.showHelp {
		usage(stdout)
		return nil, errHelp
	}
	if opts.showVer {
		fmt.Fprintln(stdout, version.String())
		return nil, errHelp
	}
	return positional, nil
}

// errHelp signals that the command has already done its work.
var errHelp = errors.New("help")

// runSurvey captures for a while and lists the access points that were seen.
func runSurvey(args []string, stdout, stderr io.Writer) int {
	opts := &options{}
	fs := newFlagSet("survey", opts, stderr)
	if _, err := parse(fs, opts, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return ExitOK
		}
		return ExitUsage
	}

	if opts.iface == "" {
		return fail(stderr, "no interface was given, use --interface")
	}
	channels, err := parseChannels(opts.channels)
	if err != nil {
		return fail(stderr, "%v", err)
	}

	if opts.duration == 0 {
		opts.duration = 30 * time.Second
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, opts.duration)
	defer cancel()

	analyzer, err := liveCapture(ctx, opts, channels, stderr)
	if err != nil {
		return fail(stderr, "%v", err)
	}

	session := analyzer.Result()
	audit.Run(session)

	printAPTable(stdout, session, opts.noColor)
	fmt.Fprintf(stdout, "\n%d access points, %d clients, %d packets\n",
		len(session.APs), len(session.Clients), session.Stats.Packets)
	return ExitOK
}

// runWatch captures for a while and reports the findings.
func runWatch(args []string, stdout, stderr io.Writer) int {
	opts := &options{}
	fs := newFlagSet("watch", opts, stderr)
	if _, err := parse(fs, opts, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return ExitOK
		}
		return ExitUsage
	}

	if opts.iface == "" {
		return fail(stderr, "no interface was given, use --interface")
	}
	channels, err := parseChannels(opts.channels)
	if err != nil {
		return fail(stderr, "%v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if opts.duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
		defer cancel()
	}

	analyzer, err := liveCapture(ctx, opts, channels, stderr)
	if err != nil {
		return fail(stderr, "%v", err)
	}

	session := analyzer.Result()
	audit.Run(session)
	fmt.Fprint(stdout, report.Text(session))
	return ExitOK
}

// runAnalyze reads a capture file and reports on it.
func runAnalyze(args []string, stdout, stderr io.Writer) int {
	opts := &options{}
	fs := newFlagSet("analyze", opts, stderr)
	positional, err := parse(fs, opts, args, stdout)
	if err != nil {
		if errors.Is(err, errHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if len(positional) == 0 {
		return fail(stderr, "no capture file was given")
	}
	path := positional[0]

	session, err := analyzeFile(path)
	if err != nil {
		return fail(stderr, "%v", err)
	}
	audit.Run(session)

	switch strings.ToLower(opts.format) {
	case "json":
		data, err := report.JSON(session)
		if err != nil {
			return fail(stderr, "%v", err)
		}
		fmt.Fprintln(stdout, string(data))
	case "html":
		page, err := report.HTML(session)
		if err != nil {
			return fail(stderr, "%v", err)
		}
		fmt.Fprint(stdout, page)
	default:
		fmt.Fprint(stdout, report.Text(session))
	}
	return ExitOK
}

// isSet reports whether the flag was given on the command line.
func isSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// formatFor picks the report format from the extension of the output file.
func formatFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		return "json"
	case ".html", ".htm":
		return "html"
	default:
		return "text"
	}
}

// runCheck reads a capture file and prints only the findings.
func runCheck(args []string, stdout, stderr io.Writer) int {
	opts := &options{}
	fs := newFlagSet("check", opts, stderr)
	positional, err := parse(fs, opts, args, stdout)
	if err != nil {
		if errors.Is(err, errHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if len(positional) == 0 {
		return fail(stderr, "no capture file was given")
	}

	session, err := analyzeFile(positional[0])
	if err != nil {
		return fail(stderr, "%v", err)
	}
	audit.Run(session)

	if len(session.Findings) == 0 {
		fmt.Fprintln(stdout, "nothing was reported")
		return ExitOK
	}
	for _, f := range session.Findings {
		fmt.Fprintf(stdout, "%s  %-14s %s\n", colorize(opts.noColor, string(f.Severity), severityColor(f.Severity)), f.ID, f.Title)
		fmt.Fprintf(stdout, "    %s\n", f.Detail)
		if f.Evidence != "" {
			fmt.Fprintf(stdout, "    evidence: %s\n", f.Evidence)
		}
		if f.Remedy != "" {
			fmt.Fprintf(stdout, "    remedy:   %s\n", f.Remedy)
		}
		fmt.Fprintln(stdout)
	}
	return ExitOK
}

// runReport writes a report of a capture file to a file.
func runReport(args []string, stdout, stderr io.Writer) int {
	opts := &options{}
	fs := newFlagSet("report", opts, stderr)
	positional, err := parse(fs, opts, args, stdout)
	if err != nil {
		if errors.Is(err, errHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if len(positional) == 0 {
		return fail(stderr, "no capture file was given")
	}
	format := strings.ToLower(opts.format)
	if !isSet(fs, "format") && opts.output != "" {
		// The extension of the output file picks the format when the
		// format was not given on the command line.
		format = formatFor(opts.output)
	}
	switch format {
	case "json", "html", "text":
	default:
		return fail(stderr, "unknown format %q", opts.format)
	}
	if opts.output == "" {
		return fail(stderr, "no output file was given, use --output")
	}

	session, err := analyzeFile(positional[0])
	if err != nil {
		return fail(stderr, "%v", err)
	}
	audit.Run(session)

	var data []byte
	switch format {
	case "json":
		data, err = report.JSON(session)
	case "html":
		var page string
		page, err = report.HTML(session)
		data = []byte(page)
	case "text":
		data = []byte(report.Text(session))
	}
	if err != nil {
		return fail(stderr, "%v", err)
	}
	if err := os.WriteFile(opts.output, data, 0o644); err != nil {
		return fail(stderr, "%v", err)
	}
	fmt.Fprintf(stdout, "the report was written to %s\n", opts.output)
	return ExitOK
}

// runIface lists the wireless interfaces of the host.
func runIface(args []string, stdout, stderr io.Writer) int {
	opts := &options{}
	fs := newFlagSet("iface", opts, stderr)
	if _, err := parse(fs, opts, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return ExitOK
		}
		return ExitUsage
	}

	names, err := capture.Interfaces()
	if err != nil {
		return fail(stderr, "%v", err)
	}
	if len(names) == 0 {
		fmt.Fprintln(stdout, "no wireless interface was found")
		return ExitOK
	}

	radio, rerr := capture.OpenRadio()
	if rerr == nil {
		defer radio.Close()
	}

	fmt.Fprintf(stdout, "%-18s %-10s %-8s %s\n", "INTERFACE", "INDEX", "TYPE", "WIPHY")
	for _, name := range names {
		index, err := capture.InterfaceIndex(name)
		if err != nil {
			continue
		}
		kind := "unknown"
		wiphy := "-"
		if radio != nil {
			if iface, err := radio.QueryInterface(name); err == nil {
				if iface.Monitor {
					kind = "monitor"
				} else {
					kind = "station"
				}
				wiphy = strconv.FormatUint(uint64(iface.Wiphy), 10)
			}
		}
		fmt.Fprintf(stdout, "%-18s %-10d %-8s %s\n", name, index, kind, wiphy)
	}
	return ExitOK
}

// liveCapture performs a capture and returns the analyzer it filled.
func liveCapture(ctx context.Context, opts *options, channels []int, stderr io.Writer) (*audit.Analyzer, error) {
	if opts.monitor {
		fmt.Fprintf(stderr, "wyrm: monitor mode takes %s off the network\n", opts.iface)
	}

	cap, err := capture.Prepare(capture.Options{
		Interface:    opts.iface,
		Channels:     channels,
		Hop:          opts.hop,
		HopInterval:  opts.hopInterval,
		Monitor:      opts.monitor,
		Filter:       opts.filter,
		Output:       opts.output,
		SudoPassword: opts.sudoPassword,
		Logger: func(format string, args ...any) {
			if !opts.quiet {
				fmt.Fprintf(stderr, "wyrm: "+format+"\n", args...)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	defer cap.Close()

	analyzer := audit.New(opts.iface)
	if !opts.quiet {
		fmt.Fprintf(stderr, "wyrm: capturing on %s, press Ctrl+C to stop\n", opts.iface)
	}
	err = cap.Run(ctx, func(pkt *pcap.Packet) {
		analyzer.Packet(pkt)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}
	return analyzer, nil
}

// analyzeFile reads a capture file and returns the audit session.
func analyzeFile(path string) (*audit.Session, error) {
	reader, err := pcap.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	analyzer := audit.New(path)
	for {
		pkt, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		analyzer.Packet(pkt)
	}
	return analyzer.Result(), nil
}

// printAPTable prints the access points of a session.
func printAPTable(w io.Writer, session *audit.Session, noColor bool) {
	aps := session.APList()
	if len(aps) == 0 {
		fmt.Fprintln(w, "no access point was seen")
		return
	}
	sort.Slice(aps, func(i, j int) bool {
		if aps[i].HasSignal != aps[j].HasSignal {
			return aps[i].HasSignal
		}
		if aps[i].Signal != aps[j].Signal {
			return aps[i].Signal > aps[j].Signal
		}
		return aps[i].BSSID < aps[j].BSSID
	})

	fmt.Fprintf(w, "%-24s %-17s %3s  %-22s %-6s %s\n", "SSID", "BSSID", "CH", "SECURITY", "GRADE", "SIGNAL")
	for _, ap := range aps {
		ssid := ap.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		signal := ""
		if ap.HasSignal {
			signal = fmt.Sprintf("%d dBm", ap.Signal)
		}
		fmt.Fprintf(w, "%-24s %-17s %3d  %-22s %-6s %s\n",
			truncate(ssid, 24), ap.BSSID, ap.Channel,
			truncate(audit.DescribeSecurity(ap.Security), 22), ap.Security.Grade, signal)
	}
}

// parseChannels reads a channel list.
func parseChannels(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("no channel was given, use --channels")
	}
	var out []int
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			from, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("invalid channel range %q", part)
			}
			to, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("invalid channel range %q", part)
			}
			if from > to {
				return nil, fmt.Errorf("invalid channel range %q", part)
			}
			// A range may cover channels that are not in use, so the
			// ones that the tool knows are taken and the others are
			// skipped.
			before := len(out)
			for n := from; n <= to; n++ {
				if _, ok := capture.ChannelByNumber(n); !ok {
					continue
				}
				out = append(out, n)
			}
			if len(out) == before {
				return nil, fmt.Errorf("the range %q holds no channel the tool knows", part)
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid channel %q", part)
		}
		if _, ok := capture.ChannelByNumber(n); !ok {
			return nil, fmt.Errorf("%d is not a channel the tool knows", n)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("no channel was given")
	}
	return out, nil
}

// fail prints an error and returns the error exit code.
func fail(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "wyrm: "+format+"\n", args...)
	return ExitError
}

// truncate shortens a string to a maximum width.
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}
