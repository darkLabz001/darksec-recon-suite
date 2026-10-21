// Package gui serves a browser based interface for the scanner.
//
// The binary embeds a single page application and exposes a small JSON
// API. A scan is started and stopped over HTTP and every result is pushed
// to the page over Server-Sent Events, so the interface updates live as
// the scan progresses.
package gui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/engine"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/osdetect"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/output"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/version"
)

//go:embed assets
var assetsFS embed.FS

// Exit codes mirror the command line interface.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// scanRequest is the body of a scan request.
type scanRequest struct {
	Targets     string  `json:"targets"`
	Ports       string  `json:"ports"`
	TopPorts    int     `json:"top_ports"`
	Engine      string  `json:"engine"`
	Detect      bool    `json:"detect"`
	OSDetect    bool    `json:"os_detect"`
	JA3         bool    `json:"ja3"`
	Favicon     bool    `json:"favicon"`
	TimeoutMs   int     `json:"timeout_ms"`
	Rate        float64 `json:"rate"`
	Concurrency int     `json:"concurrency"`
	ShowAll     bool    `json:"show_all"`
	SourceAddr  string  `json:"source_addr"`
}

// resultJSON is the wire representation of a scan result.
type resultJSON struct {
	IP       string           `json:"ip"`
	Port     int              `json:"port"`
	Protocol string           `json:"protocol"`
	State    string           `json:"state"`
	Service  string           `json:"service,omitempty"`
	Product  string           `json:"product,omitempty"`
	Version  string           `json:"version,omitempty"`
	Extra    string           `json:"extra,omitempty"`
	CPE      string           `json:"cpe,omitempty"`
	Banner   string           `json:"banner,omitempty"`
	Method   string           `json:"method,omitempty"`
	RTTMs    float64          `json:"rtt_ms"`
	JA3      string           `json:"ja3,omitempty"`
	JA3S     string           `json:"ja3s,omitempty"`
	Favicon  string           `json:"favicon,omitempty"`
	Title    string           `json:"title,omitempty"`
	Server   string           `json:"server,omitempty"`
	OS       *osdetect.Result `json:"os,omitempty"`
}

// event is a Server-Sent Event payload.
type event struct {
	Type    string      `json:"type"`
	Result  *resultJSON `json:"result,omitempty"`
	Stats   *statsJSON  `json:"stats,omitempty"`
	Error   string      `json:"error,omitempty"`
	Stopped bool        `json:"stopped,omitempty"`
	Total   int64       `json:"total,omitempty"`
}

// statsJSON carries the live scan counters.
type statsJSON struct {
	Running  bool    `json:"running"`
	Total    int64   `json:"total"`
	Open     int64   `json:"open"`
	Closed   int64   `json:"closed"`
	Filtered int64   `json:"filtered"`
	Done     int64   `json:"done"`
	Elapsed  float64 `json:"elapsed_seconds"`
}

// hub broadcasts events to the connected clients.
type hub struct {
	mu   sync.Mutex
	subs map[chan event]struct{}
}

func newHub() *hub {
	return &hub{subs: make(map[chan event]struct{})}
}

// subscribe registers a listener and returns its channel.
func (h *hub) subscribe() chan event {
	ch := make(chan event, 512)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// publish sends an event to every listener. Slow listeners are dropped
// rather than allowed to stall the scan.
func (h *hub) publish(ev event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// manager owns the current scan and its accumulated results.
type manager struct {
	hub *hub

	mu      sync.Mutex
	run     *runState
	results []engine.Result
	total   int64
	counts  map[string]int64
	started time.Time
}

// runState carries the cancellation of the active scan.
type runState struct {
	cancel context.CancelFunc
}

func newManager() *manager {
	return &manager{
		hub:    newHub(),
		counts: map[string]int64{},
	}
}

// start parses the request and begins a scan, stopping any active scan.
func (m *manager) start(req scanRequest) error {
	ctx, cancel := context.WithCancel(context.Background())
	hosts, portList, cfg, engineName, err := buildScan(req)
	if err != nil {
		cancel()
		return err
	}

	m.stop()
	m.mu.Lock()
	m.run = &runState{cancel: cancel}
	m.results = m.results[:0]
	m.total = int64(len(hosts)) * int64(len(portList))
	m.counts = map[string]int64{}
	m.started = time.Now()
	m.mu.Unlock()

	m.hub.publish(event{Type: "start", Total: m.total})

	go m.runScan(ctx, engineName, hosts, portList, cfg)
	return nil
}

// stop cancels the active scan, if any.
func (m *manager) stop() {
	m.mu.Lock()
	run := m.run
	m.run = nil
	m.mu.Unlock()
	if run != nil {
		run.cancel()
	}
}

// running reports whether a scan is in progress.
func (m *manager) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.run != nil
}

// handleResult stores a result and pushes it to the clients.
func (m *manager) handleResult(res engine.Result) {
	m.mu.Lock()
	m.results = append(m.results, res)
	m.counts[string(res.State)]++
	m.mu.Unlock()

	m.hub.publish(event{Type: "result", Result: toResultJSON(res)})
}

// stats returns a snapshot of the scan counters.
func (m *manager) stats() statsJSON {
	m.mu.Lock()
	defer m.mu.Unlock()
	open := m.counts["open"]
	closed := m.counts["closed"]
	filtered := m.counts["filtered"]
	done := open + closed + filtered
	return statsJSON{
		Running:  m.run != nil,
		Total:    m.total,
		Open:     open,
		Closed:   closed,
		Filtered: filtered,
		Done:     done,
		Elapsed:  time.Since(m.started).Seconds(),
	}
}

func (m *manager) publishStats() {
	m.hub.publish(event{Type: "stats", Stats: statsPtr(m.stats())})
}

// runScan drives the engine and publishes results, stats and completion.
func (m *manager) runScan(ctx context.Context, engineName string, hosts []target.Host, portList []uint16, cfg engine.Config) {
	results := make(chan engine.Result, 1024)
	runErr := make(chan error, 1)

	go func() {
		err := scanEngine(ctx, engineName, hosts, portList, cfg, results)
		close(results)
		runErr <- err
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case res, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			m.handleResult(res)
		case err := <-runErr:
			m.finish(err)
			return
		case <-ticker.C:
			m.publishStats()
		}
	}
}

// finish records the end of a scan.
func (m *manager) finish(err error) {
	m.mu.Lock()
	m.run = nil
	m.mu.Unlock()

	ev := event{Type: "done"}
	switch {
	case errors.Is(err, context.Canceled):
		ev.Stopped = true
	case err != nil:
		ev.Error = err.Error()
	}
	m.hub.publish(ev)
	m.publishStats()
}

// buildScan turns a request into engine inputs.
func buildScan(req scanRequest) ([]target.Host, []uint16, engine.Config, string, error) {
	targets := splitFields(req.Targets)
	if len(targets) == 0 {
		return nil, nil, engine.Config{}, "", errors.New("no targets specified")
	}

	hosts, err := target.Parse(context.Background(), targets, target.Options{
		ResolveHostnames: true,
	})
	if err != nil {
		return nil, nil, engine.Config{}, "", err
	}
	if len(hosts) == 0 {
		return nil, nil, engine.Config{}, "", errors.New("no targets resolved")
	}

	name := strings.ToLower(strings.TrimSpace(req.Engine))
	if name == "" {
		name = "connect"
	}

	udp := name == "udp"
	portList, err := buildPortList(req, udp)
	if err != nil {
		return nil, nil, engine.Config{}, "", err
	}
	if len(portList) == 0 {
		return nil, nil, engine.Config{}, "", errors.New("no ports selected")
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = engine.DefaultTimeout
	}

	cfg := engine.Config{
		Timeout:        timeout,
		Detect:         req.Detect,
		EnableJA3:      req.JA3,
		EnableHTTP:     true,
		EnableFavicon:  req.Favicon,
		Rate:           req.Rate,
		Concurrency:    req.Concurrency,
		MinConcurrency: engine.DefaultMinConcurrency,
		MaxConcurrency: engine.DefaultMaxConcurrency,
		Order:          engine.OrderAuto,
		OSDetect:       req.OSDetect,
	}

	if req.SourceAddr != "" {
		addr, err := netip.ParseAddr(req.SourceAddr)
		if err != nil {
			return nil, nil, engine.Config{}, "", fmt.Errorf("invalid source address %q: %w", req.SourceAddr, err)
		}
		cfg.SourceAddr = addr.Unmap()
	}

	return hosts, portList, cfg, name, nil
}

// buildPortList resolves the port specification for an engine.
func buildPortList(req scanRequest, udp bool) ([]uint16, error) {
	switch {
	case req.TopPorts > 0:
		if udp {
			if req.TopPorts > ports.TopUDPLen() {
				return nil, fmt.Errorf("the popularity list only covers %d UDP ports", ports.TopUDPLen())
			}
			return ports.TopUDP(req.TopPorts), nil
		}
		if req.TopPorts > ports.TopLen() {
			return nil, fmt.Errorf("the popularity list only covers %d ports", ports.TopLen())
		}
		return ports.Top(req.TopPorts), nil
	case strings.TrimSpace(req.Ports) != "":
		set, err := ports.Parse(req.Ports)
		if err != nil {
			return nil, err
		}
		if udp {
			if len(set.UDP) > 0 {
				return set.UDP, nil
			}
			// A bare specification in the UDP engine names UDP ports.
			return set.TCP, nil
		}
		return set.TCP, nil
	default:
		if udp {
			return ports.TopUDP(50), nil
		}
		return ports.Top(1000), nil
	}
}

// scanEngine dispatches to the requested engine.
func scanEngine(ctx context.Context, name string, hosts []target.Host, portList []uint16, cfg engine.Config, out chan<- engine.Result) error {
	switch name {
	case "", "connect", "tcp", "tcp-connect":
		return engine.NewConnectScanner(cfg).Scan(ctx, hosts, portList, out)
	case "syn", "tcp-syn":
		s, err := engine.NewSYNScanner(cfg)
		if err != nil {
			return err
		}
		return s.Scan(ctx, hosts, portList, out)
	case "udp":
		s, err := engine.NewUDPScanner(cfg)
		if err != nil {
			return err
		}
		return s.Scan(ctx, hosts, portList, out)
	default:
		return fmt.Errorf("unknown engine %q", name)
	}
}

// splitFields splits a specification on commas and whitespace.
func splitFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func toResultJSON(res engine.Result) *resultJSON {
	// An OS detection result carries the fingerprint instead of a port.
	if res.OS != nil {
		return &resultJSON{IP: res.Addr.String(), OS: res.OS}
	}
	out := &resultJSON{
		IP:       res.Addr.String(),
		Port:     int(res.Port),
		Protocol: string(res.Proto),
		State:    string(res.State),
		RTTMs:    float64(res.RTT.Microseconds()) / 1000,
	}
	if res.Service == nil {
		return out
	}
	out.Service = res.Service.Service
	out.Product = res.Service.Product
	out.Version = res.Service.Version
	out.Extra = res.Service.Extra
	out.CPE = res.Service.CPE
	out.Banner = res.Service.Banner
	out.Method = res.Service.Method
	out.JA3 = res.Service.JA3
	out.JA3S = res.Service.JA3S
	out.Favicon = res.Service.Favicon
	if res.Service.HTTP != nil {
		out.Title = res.Service.HTTP.Title
		out.Server = res.Service.HTTP.Server
	}
	return out
}

func statsPtr(s statsJSON) *statsJSON { return &s }

// Server is the HTTP handler for the interface.
type Server struct {
	mgr  *manager
	root fs.FS
}

// NewServer builds the HTTP handler.
func NewServer() (*Server, error) {
	root, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return nil, err
	}
	return &Server{mgr: newManager(), root: root}, nil
}

// Handler returns the HTTP handler that serves the interface and its API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(http.FS(s.root)))
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/export", s.handleExport)

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       version.Get(),
		"syn_available": engine.SYNAvailable(),
	})
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	s.mgr.mu.Lock()
	results := make([]resultJSON, 0, len(s.mgr.results))
	for _, res := range s.mgr.results {
		results = append(results, *toResultJSON(res))
	}
	s.mgr.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"stats":   s.mgr.stats(),
		"results": results,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req scanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if err := s.mgr.start(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started", "stats": s.mgr.stats()})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.mgr.stop()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.mgr.hub.subscribe()
	defer s.mgr.hub.unsubscribe(ch)

	// Replay the current state so a freshly connected client sees the scan
	// it may have missed.
	if s.mgr.running() {
		writeSSE(w, flusher, event{Type: "start", Total: s.mgr.total})
		writeSSE(w, flusher, event{Type: "stats", Stats: statsPtr(s.mgr.stats())})
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, flusher, ev)
		}
	}
}

func writeSSE(w io.Writer, flusher http.Flusher, ev event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	s.mgr.mu.Lock()
	results := append([]engine.Result(nil), s.mgr.results...)
	s.mgr.mu.Unlock()

	format := output.Format(r.URL.Query().Get("format"))
	var name string
	switch format {
	case output.FormatJSON:
		name = "vantage-results.json"
	case output.FormatCSV:
		name = "vantage-results.csv"
	case output.FormatJSONL:
		name = "vantage-results.jsonl"
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown format"})
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))

	writer, err := output.New(output.Options{Format: format, Output: w, ShowAll: true})
	if err != nil {
		return
	}
	for _, res := range results {
		_ = writer.Write(res)
	}
	_ = writer.Close()
}

// Run executes the gui subcommand and blocks until interrupted.
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vantage gui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8787", "address to listen on")
	openBrowser := fs.Bool("open", true, "open the interface in a browser")
	noOpen := fs.Bool("no-open", false, "do not open a browser")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitUsage
		}
		return ExitUsage
	}

	server, err := NewServer()
	if err != nil {
		fmt.Fprintf(stderr, "vantage gui: %v\n", err)
		return ExitError
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "vantage gui: listening on %s: %v\n", *listen, err)
		return ExitError
	}

	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	if strings.HasPrefix(ln.Addr().String(), "0.0.0.0:") {
		url = fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port)
	}

	fmt.Fprintf(stdout, "vantage gui running at %s\n", url)
	fmt.Fprintf(stdout, "press Ctrl+C to stop\n")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- http.Serve(ln, server.Handler())
	}()

	if *openBrowser && !*noOpen {
		launchBrowser(url)
	}

	select {
	case <-ctx.Done():
		_ = ln.Close()
		return ExitOK
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "vantage gui: %v\n", err)
			return ExitError
		}
		return ExitOK
	}
}

// launchBrowser opens the given URL in the first available browser.
func launchBrowser(url string) {
	for _, candidate := range []string{"xdg-open", "firefox", "firefox-esr", "chromium", "chromium-browser", "google-chrome"} {
		if path, err := exec.LookPath(candidate); err == nil {
			cmd := exec.Command(path, url)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if err := cmd.Start(); err == nil {
				go func() { _ = cmd.Wait() }()
				return
			}
		}
	}
}
