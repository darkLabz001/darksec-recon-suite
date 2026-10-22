package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/engine"
)

// parseArgs parses a command line into an options structure.
func parseArgs(t *testing.T, args ...string) *options {
	t.Helper()
	opts := &options{}
	fs := flag.NewFlagSet("vantage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := parse(fs, opts, args, io.Discard); err != nil {
		t.Fatalf("parse(%v) returned an error: %v", args, err)
	}
	return opts
}

func TestParseTargets(t *testing.T) {
	opts := parseArgs(t, "-t", "127.0.0.1,127.0.0.2", "-t", "127.0.0.3", "127.0.0.4")
	want := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"}
	if len(opts.targets) != len(want) {
		t.Fatalf("the targets are %v, want %v", opts.targets, want)
	}
	for i := range want {
		if opts.targets[i] != want[i] {
			t.Errorf("target %d is %q, want %q", i, opts.targets[i], want[i])
		}
	}
}

func TestParseLongFlags(t *testing.T) {
	opts := parseArgs(t,
		"--targets", "127.0.0.1",
		"--ports", "80,443",
		"--engine", "syn",
		"--timeout", "2s",
		"--concurrency", "128",
		"--rate", "500",
		"--order", "port",
		"--detect-services",
		"--no-color",
		"--all",
		"--quiet",
		"--format", "json",
	)
	if opts.portSpec != "80,443" {
		t.Errorf("the port specification is %q", opts.portSpec)
	}
	if opts.engine != "syn" {
		t.Errorf("the engine is %q", opts.engine)
	}
	if opts.timeout != 2*time.Second {
		t.Errorf("the timeout is %v", opts.timeout)
	}
	if opts.concurrency != 128 {
		t.Errorf("the concurrency is %d", opts.concurrency)
	}
	if opts.rate != 500 {
		t.Errorf("the rate is %v", opts.rate)
	}
	if opts.order != "port" {
		t.Errorf("the order is %q", opts.order)
	}
	if !opts.detect {
		t.Error("service detection was not enabled")
	}
	if !opts.noColor || !opts.showAll || !opts.quiet {
		t.Error("a boolean flag was not set")
	}
	if opts.format != "json" {
		t.Errorf("the format is %q", opts.format)
	}
}

func TestParseRejectsUnknownFlags(t *testing.T) {
	opts := &options{}
	fs := flag.NewFlagSet("vantage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := parse(fs, opts, []string{"--not-a-flag"}, io.Discard); err == nil {
		t.Fatal("parse accepted an unknown flag")
	}
}

func TestParseDefaults(t *testing.T) {
	opts := parseArgs(t, "127.0.0.1")
	if opts.engine != "connect" {
		t.Errorf("the default engine is %q, want connect", opts.engine)
	}
	if opts.timeout != engine.DefaultTimeout {
		t.Errorf("the default timeout is %v", opts.timeout)
	}
	if opts.format != "text" {
		t.Errorf("the default format is %q, want text", opts.format)
	}
	if opts.order != "auto" {
		t.Errorf("the default order is %q, want auto", opts.order)
	}
}

func TestBuildPortSetFromSpecification(t *testing.T) {
	set, err := buildPortSet(&options{portSpec: "1-3,80", engine: "connect"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.TCP) != 4 {
		t.Errorf("the TCP ports are %v, want four of them", set.TCP)
	}
	if len(set.UDP) != 0 {
		t.Errorf("the UDP ports are %v, want none", set.UDP)
	}
}

func TestBuildPortSetHonoursProtocolPrefixes(t *testing.T) {
	set, err := buildPortSet(&options{portSpec: "T:80,U:53", engine: "connect"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.TCP) != 1 || set.TCP[0] != 80 {
		t.Errorf("the TCP ports are %v, want [80]", set.TCP)
	}
	if len(set.UDP) != 1 || set.UDP[0] != 53 {
		t.Errorf("the UDP ports are %v, want [53]", set.UDP)
	}
}

func TestBuildPortSetTreatsBarePortsAsUDPInTheUDPEngine(t *testing.T) {
	set, err := buildPortSet(&options{portSpec: "53,67", engine: "udp"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.TCP) != 0 {
		t.Errorf("the TCP ports are %v, want none", set.TCP)
	}
	if len(set.UDP) != 2 {
		t.Errorf("the UDP ports are %v, want two of them", set.UDP)
	}
}

func TestBuildPortSetKeepsExplicitPrefixesInTheUDPEngine(t *testing.T) {
	set, err := buildPortSet(&options{portSpec: "T:80,U:53", engine: "udp"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.UDP) != 1 || set.UDP[0] != 53 {
		t.Errorf("the UDP ports are %v, want [53]", set.UDP)
	}
}

func TestBuildPortSetTopPorts(t *testing.T) {
	set, err := buildPortSet(&options{topPorts: 10, engine: "connect"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.TCP) != 10 {
		t.Errorf("the TCP ports are %d, want 10", len(set.TCP))
	}

	udpset, err := buildPortSet(&options{topPorts: 10, engine: "udp"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(udpset.UDP) != 10 {
		t.Errorf("the UDP ports are %d, want 10", len(udpset.UDP))
	}
}

func TestBuildPortSetRejectsAnImpossibleTopPortCount(t *testing.T) {
	if _, err := buildPortSet(&options{topPorts: 1000000, engine: "connect"}); err == nil {
		t.Fatal("buildPortSet accepted an impossible port count")
	}
}

func TestBuildPortSetExcludesPorts(t *testing.T) {
	set, err := buildPortSet(&options{portSpec: "1-10", excludePorts: "5,7", engine: "connect"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.TCP) != 8 {
		t.Errorf("the TCP ports are %v, want eight of them", set.TCP)
	}
	for _, p := range set.TCP {
		if p == 5 || p == 7 {
			t.Errorf("the excluded port %d is still present", p)
		}
	}
}

func TestBuildPortSetRejectsBadSpecifications(t *testing.T) {
	if _, err := buildPortSet(&options{portSpec: "notaport", engine: "connect"}); err == nil {
		t.Fatal("buildPortSet accepted an invalid port")
	}
	if _, err := buildPortSet(&options{portSpec: "99999", engine: "connect"}); err == nil {
		t.Fatal("buildPortSet accepted an out of range port")
	}
}

func TestBuildPortSetDefaults(t *testing.T) {
	set, err := buildPortSet(&options{engine: "connect"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(set.TCP) == 0 {
		t.Error("the default port set is empty")
	}

	udpset, err := buildPortSet(&options{engine: "udp"})
	if err != nil {
		t.Fatalf("buildPortSet returned an error: %v", err)
	}
	if len(udpset.UDP) == 0 {
		t.Error("the default UDP port set is empty")
	}
}

func TestSpecHasProtocolPrefix(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"80,443", false},
		{"T:80", true},
		{"U:53", true},
		{"80,U:53", true},
		{"", false},
	}
	for _, c := range cases {
		if got := specHasProtocolPrefix(c.spec); got != c.want {
			t.Errorf("specHasProtocolPrefix(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestBuildEngineConfigOrder(t *testing.T) {
	cases := map[string]engine.Order{
		"host": engine.OrderHost,
		"port": engine.OrderPort,
		"auto": engine.OrderAuto,
		"":     engine.OrderAuto,
	}
	for name, want := range cases {
		cfg, err := buildEngineConfig(&options{order: name})
		if err != nil {
			t.Fatalf("buildEngineConfig(%q) returned an error: %v", name, err)
		}
		if cfg.Order != want {
			t.Errorf("buildEngineConfig(%q).Order = %v, want %v", name, cfg.Order, want)
		}
	}

	if _, err := buildEngineConfig(&options{order: "sideways"}); err == nil {
		t.Fatal("buildEngineConfig accepted an unknown order")
	}
}

func TestBuildEngineConfigSourceAddress(t *testing.T) {
	cfg, err := buildEngineConfig(&options{sourceAddr: "::ffff:127.0.0.1"})
	if err != nil {
		t.Fatalf("buildEngineConfig returned an error: %v", err)
	}
	if cfg.SourceAddr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("the source address is %v", cfg.SourceAddr)
	}

	if _, err := buildEngineConfig(&options{sourceAddr: "not-an-address"}); err == nil {
		t.Fatal("buildEngineConfig accepted an invalid source address")
	}
}

func TestBuildEngineConfigProbesAndFallbacks(t *testing.T) {
	cfg, err := buildEngineConfig(&options{probes: "http, ssh", fallbacks: "http,https"})
	if err != nil {
		t.Fatalf("buildEngineConfig returned an error: %v", err)
	}
	if len(cfg.Protocols) != 2 || cfg.Protocols[0] != "http" || cfg.Protocols[1] != "ssh" {
		t.Errorf("the protocols are %v", cfg.Protocols)
	}
	if len(cfg.Fallbacks) != 2 || cfg.Fallbacks[0] != "http" || cfg.Fallbacks[1] != "https" {
		t.Errorf("the fallbacks are %v", cfg.Fallbacks)
	}
}

func TestBuildEngineConfigDetectionFlags(t *testing.T) {
	cfg, err := buildEngineConfig(&options{detect: true, ja3: true, favicon: true})
	if err != nil {
		t.Fatalf("buildEngineConfig returned an error: %v", err)
	}
	if !cfg.Detect {
		t.Error("detection was not enabled")
	}
	if !cfg.EnableJA3 {
		t.Error("JA3 was not enabled")
	}
	if !cfg.EnableFavicon {
		t.Error("favicon collection was not enabled")
	}

	cfg, err = buildEngineConfig(&options{detect: true, noDetect: true})
	if err != nil {
		t.Fatalf("buildEngineConfig returned an error: %v", err)
	}
	if cfg.Detect {
		t.Error("detection was enabled despite --no-detect")
	}
}

func TestBuildEngineConfigLoadsFingerprintRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := `{"rules":[{"name":"demo","service":"http","pattern":"DemoServer ([0-9.]+)","product":"Demo","version_group":1}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildEngineConfig(&options{fingerprintRules: path})
	if err != nil {
		t.Fatalf("buildEngineConfig returned an error: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("the rule set holds %d rules, want 1", len(cfg.Rules))
	}
	if cfg.Rules[0].Product != "Demo" {
		t.Errorf("the rule product is %q", cfg.Rules[0].Product)
	}

	if _, err := buildEngineConfig(&options{fingerprintRules: filepath.Join(dir, "missing.json")}); err == nil {
		t.Fatal("buildEngineConfig accepted a missing rules file")
	}
}

func TestFindConfigFlag(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--config", "a.json"}, "a.json"},
		{[]string{"-config", "a.json"}, "a.json"},
		{[]string{"--config=a.json"}, "a.json"},
		{[]string{"-config=a.json"}, "a.json"},
		{[]string{"--ports", "80"}, ""},
	}
	for _, c := range cases {
		if got := findConfigFlag(c.args); got != c.want {
			t.Errorf("findConfigFlag(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestApplyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
		"timeout": "3s",
		"concurrency": 64,
		"rate": 250,
		"ports": "1-100",
		"engine": "udp",
		"detect": true,
		"format": "jsonl",
		"user_agent": "vantage-test",
		"ja3": true,
		"favicon": true,
		"probe_timeout": "7s"
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := &options{}
	if err := applyConfig(opts, path); err != nil {
		t.Fatalf("applyConfig returned an error: %v", err)
	}
	if opts.timeout != 3*time.Second {
		t.Errorf("the timeout is %v", opts.timeout)
	}
	if opts.concurrency != 64 {
		t.Errorf("the concurrency is %d", opts.concurrency)
	}
	if opts.rate != 250 {
		t.Errorf("the rate is %v", opts.rate)
	}
	if opts.portSpec != "1-100" {
		t.Errorf("the port specification is %q", opts.portSpec)
	}
	if opts.engine != "udp" {
		t.Errorf("the engine is %q", opts.engine)
	}
	if !opts.detect || !opts.ja3 || !opts.favicon {
		t.Error("a boolean option was not applied")
	}
	if opts.format != "jsonl" {
		t.Errorf("the format is %q", opts.format)
	}
	if opts.userAgent != "vantage-test" {
		t.Errorf("the user agent is %q", opts.userAgent)
	}
	if opts.probeTimeout != 7*time.Second {
		t.Errorf("the probe timeout is %v", opts.probeTimeout)
	}
}

func TestApplyConfigReportsBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyConfig(&options{}, path); err == nil {
		t.Fatal("applyConfig accepted a malformed file")
	}
	if err := applyConfig(&options{}, filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("applyConfig accepted a missing file")
	}
}

func TestCommandLineOverridesTheConfigurationFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"timeout":"3s","concurrency":64}`), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := parseArgs(t, "--config", path, "--timeout", "9s")
	if opts.timeout != 9*time.Second {
		t.Errorf("the timeout is %v, want 9s", opts.timeout)
	}
	if opts.concurrency != 64 {
		t.Errorf("the concurrency is %d, want the value from the file", opts.concurrency)
	}
}

func TestRunPrintsTheHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--help"}, &stdout, &stderr)
	if code != ExitOK {
		t.Errorf("the exit code is %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("the help output does not contain a usage section: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--top-ports") {
		t.Errorf("the help output does not list the flags: %q", stdout.String())
	}
}

func TestRunPrintsTheVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--version"}, &stdout, &stderr)
	if code != ExitOK {
		t.Errorf("the exit code is %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "vantage") {
		t.Errorf("the version output is %q", stdout.String())
	}
}

func TestRunRequiresTargets(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{}, &stdout, &stderr)
	if code != ExitError {
		t.Errorf("the exit code is %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "no targets") {
		t.Errorf("the error output is %q", stderr.String())
	}
}

func TestRunRejectsAnUnknownEngine(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--engine", "carrier-pigeon", "127.0.0.1"}, &stdout, &stderr)
	if code != ExitError {
		t.Errorf("the exit code is %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "unknown engine") {
		t.Errorf("the error output is %q", stderr.String())
	}
}

func TestRunRejectsAnUnknownOrder(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--order", "sideways", "127.0.0.1"}, &stdout, &stderr)
	if code != ExitError {
		t.Errorf("the exit code is %d, want %d", code, ExitError)
	}
}

func TestRunScansALocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"-p", fmt.Sprint(port),
		"--format", "json",
		"--no-color",
		"127.0.0.1",
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("the exit code is %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}

	var results []struct {
		IP    string `json:"ip"`
		Port  int    `json:"port"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("the output is not valid JSON: %v (%q)", err, stdout.String())
	}
	if len(results) != 1 {
		t.Fatalf("the output holds %d results, want 1", len(results))
	}
	if results[0].Port != int(port) {
		t.Errorf("the reported port is %d, want %d", results[0].Port, port)
	}
	if results[0].State != "open" {
		t.Errorf("the reported state is %q, want open", results[0].State)
	}
	if results[0].IP != "127.0.0.1" {
		t.Errorf("the reported address is %q", results[0].IP)
	}
}

func TestRunWritesToAFile(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"-p", fmt.Sprint(port),
		"--format", "json",
		"-o", path,
		"127.0.0.1",
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("the exit code is %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("the standard output holds %q, want nothing", stdout.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), fmt.Sprint(port)) {
		t.Errorf("the output file %q does not mention the port", data)
	}
}

func TestRunRejectsAnInvalidTemplate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"--format", "template",
		"-p", "1",
		"127.0.0.1",
	}, &stdout, &stderr)
	if code != ExitError {
		t.Errorf("the exit code is %d, want %d", code, ExitError)
	}
}

func TestRunDetectsAService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// A minimal HTTP greeting.
			go func() {
				buf := make([]byte, 1024)
				conn.Read(buf)
				conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: vantage-test\r\nContent-Length: 0\r\n\r\n"))
				conn.Close()
			}()
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"-p", fmt.Sprint(port),
		"-s",
		"--format", "json",
		"127.0.0.1",
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("the exit code is %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"service\"") {
		t.Errorf("the output %q carries no service information", stdout.String())
	}
}
