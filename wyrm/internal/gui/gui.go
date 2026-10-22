// Package gui serves a browser based interface for the auditor.
//
// The binary embeds a single page application and exposes a small JSON API.
// A capture is started and stopped over HTTP and every result is pushed to
// the page over Server-Sent Events, so the interface updates live as the
// capture progresses.
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
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/capture"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/pcap"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/report"
	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/version"
)

//go:embed assets
var assetsFS embed.FS

// Exit codes mirror the command line interface.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// captureRequest is the body of a capture request.
type captureRequest struct {
	Interface    string `json:"interface"`
	Channels     string `json:"channels"`
	Hop          bool   `json:"hop"`
	HopInterval  int    `json:"hop_interval_ms"`
	Monitor      bool   `json:"monitor"`
	Filter       string `json:"filter"`
	Output       string `json:"output"`
	SudoPassword string `json:"sudo_password"`
	Duration     int    `json:"duration_s"`
}

// event is one message pushed to the browser.
type event struct {
	Type    string    `json:"type"`
	State   *snapshot `json:"state,omitempty"`
	Error   string    `json:"error,omitempty"`
	Stopped bool      `json:"stopped,omitempty"`
}

// snapshot is the state of the audit at a point in time.
type snapshot struct {
	Running  bool           `json:"running"`
	Source   string         `json:"source"`
	Started  string         `json:"started"`
	Ended    string         `json:"ended"`
	Error    string         `json:"error"`
	Stats    audit.Stats    `json:"stats"`
	APs      []apView       `json:"access_points"`
	Findings []findingView  `json:"findings"`
	Verdict  string         `json:"verdict"`
	Grade    string         `json:"grade"`
	Summary  map[string]int `json:"counts"`
}

// apView is one access point in the interface.
type apView struct {
	BSSID     string   `json:"bssid"`
	SSID      string   `json:"ssid"`
	Hidden    bool     `json:"hidden"`
	Channel   int      `json:"channel"`
	Signal    int      `json:"signal"`
	HasSignal bool     `json:"has_signal"`
	Beacons   int      `json:"beacons"`
	Security  string   `json:"security"`
	Grade     string   `json:"grade"`
	Score     int      `json:"score"`
	AKMs      []string `json:"akm_suites"`
	Ciphers   []string `json:"pairwise_ciphers"`
	MFPR      bool     `json:"mfpr"`
	MFPC      bool     `json:"mfpc"`
	Findings  int      `json:"findings"`
}

// findingView is one finding in the interface.
type findingView struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Family   string `json:"family"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	Remedy   string `json:"remedy"`
}

// hub fans events out to the connected browsers.
type hub struct {
	mu   sync.Mutex
	subs map[chan event]struct{}
}

func newHub() *hub { return &hub{subs: map[chan event]struct{}{}} }

func (h *hub) subscribe() chan event {
	ch := make(chan event, 16)
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

// manager owns the current capture and the audit it produces.
type manager struct {
	hub *hub

	mu       sync.Mutex
	running  bool
	analyzer *audit.Analyzer
	session  *audit.Session
	cancel   context.CancelFunc
	started  time.Time
	ended    time.Time
	lastErr  string
	source   string
}

func newManager() *manager { return &manager{hub: newHub()} }

// start parses the request and begins a capture, stopping any active one.
func (m *manager) start(req captureRequest) error {
	if strings.TrimSpace(req.Interface) == "" {
		return errors.New("no interface was given")
	}

	channels, err := parseChannels(req.Channels)
	if err != nil {
		return err
	}

	hop := req.Hop
	if len(channels) == 1 {
		hop = false
	}
	interval := time.Duration(req.HopInterval) * time.Millisecond
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}

	m.stop()

	ctx, cancel := context.WithCancel(context.Background())

	opts := capture.Options{
		Interface:    req.Interface,
		Channels:     channels,
		Hop:          hop,
		HopInterval:  interval,
		Monitor:      req.Monitor,
		Filter:       strings.TrimSpace(req.Filter),
		Output:       strings.TrimSpace(req.Output),
		SudoPassword: req.SudoPassword,
		Logger: func(format string, args ...any) {
			m.hub.publish(event{Type: "log", Error: fmt.Sprintf(format, args...)})
		},
	}

	cap, err := capture.Prepare(opts)
	if err != nil {
		cancel()
		return err
	}

	analyzer := audit.New(req.Interface)

	m.mu.Lock()
	m.running = true
	m.analyzer = analyzer
	m.session = analyzer.Result()
	m.cancel = cancel
	m.started = time.Now()
	m.ended = time.Time{}
	m.lastErr = ""
	m.source = req.Interface
	m.mu.Unlock()

	m.hub.publish(event{Type: "start", State: m.snapshot()})

	go m.run(ctx, cap, analyzer, time.Duration(req.Duration)*time.Second)
	return nil
}

// run performs the capture and publishes the results.
func (m *manager) run(ctx context.Context, cap *capture.Capture, analyzer *audit.Analyzer, limit time.Duration) {
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}

	err := cap.Run(ctx, func(pkt *pcap.Packet) {
		m.mu.Lock()
		analyzer.Packet(pkt)
		m.mu.Unlock()
	})
	_ = cap.Close()

	m.mu.Lock()
	m.running = false
	m.ended = time.Now()
	if err != nil && !errors.Is(err, context.Canceled) {
		m.lastErr = err.Error()
	}
	session := analyzer.Result()
	m.session = session
	m.mu.Unlock()

	audit.Run(session)

	ev := event{Type: "done", State: m.snapshot()}
	if err != nil && !errors.Is(err, context.Canceled) {
		ev.Error = err.Error()
	}
	m.hub.publish(ev)
}

// stop cancels the active capture, if any.
func (m *manager) stop() {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// isRunning reports whether a capture is in progress.
func (m *manager) isRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// snapshot builds the current state of the audit.
func (m *manager) snapshot() *snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := &snapshot{
		Running: m.running,
		Source:  m.source,
		Error:   m.lastErr,
		Summary: map[string]int{},
	}
	if !m.started.IsZero() {
		out.Started = m.started.Format(time.RFC3339)
	}
	if !m.ended.IsZero() {
		out.Ended = m.ended.Format(time.RFC3339)
	}
	if m.analyzer == nil {
		return out
	}

	session := m.analyzer.Result()
	out.Stats = session.Stats

	// The checks run on a copy so that the live view does not disturb the
	// session that is still being written to.
	live := session.Clone()
	audit.Run(live)
	for _, f := range live.Findings {
		out.Findings = append(out.Findings, findingView{
			ID:       f.ID,
			Title:    f.Title,
			Severity: string(f.Severity),
			Family:   f.Family,
			Target:   f.Target,
			Detail:   f.Detail,
			Evidence: f.Evidence,
			Remedy:   f.Remedy,
		})
	}
	sev, grade := live.Overall()
	out.Verdict = string(sev)
	out.Grade = grade
	for level, n := range live.CountBySeverity() {
		out.Summary[string(level)] = n
	}

	for _, ap := range live.APList() {
		out.APs = append(out.APs, apView{
			BSSID:     ap.BSSID,
			SSID:      ap.SSID,
			Hidden:    ap.Hidden,
			Channel:   ap.Channel,
			Signal:    ap.Signal,
			HasSignal: ap.HasSignal,
			Beacons:   ap.Beacons,
			Security:  audit.DescribeSecurity(ap.Security),
			Grade:     ap.Security.Grade,
			Score:     ap.Security.Score,
			AKMs:      ap.Security.AKMs,
			Ciphers:   ap.Security.Ciphers,
			MFPR:      ap.Security.MFPR,
			MFPC:      ap.Security.MFPC,
			Findings:  countAPFindings(live, ap.BSSID),
		})
	}
	return out
}

// countAPFindings counts the findings that name an access point.
func countAPFindings(s *audit.Session, bssid string) int {
	n := 0
	for _, f := range s.Findings {
		if f.Target == bssid {
			n++
		}
	}
	return n
}

// parseChannels reads a channel list such as "1,6,11" or "36-48".
func parseChannels(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("no channel was given")
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
			for n := from; n <= to; n++ {
				if _, ok := capture.ChannelByNumber(n); !ok {
					return nil, fmt.Errorf("%d is not a channel the tool knows", n)
				}
				out = append(out, n)
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
	mux.HandleFunc("/api/capture", s.handleCapture)
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
	ifaces, err := capture.Interfaces()
	if err != nil {
		ifaces = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version.Get(),
		"interfaces": ifaces,
		"root":       capture.IsRoot(),
		"channels":   channelList(),
	})
}

// channelList returns the channels the interface offers.
func channelList() []map[string]any {
	var out []map[string]any
	for _, c := range capture.Channels() {
		out = append(out, map[string]any{
			"number": c.Number,
			"freq":   c.Freq,
			"band":   c.Band,
		})
	}
	return out
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.snapshot())
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req captureRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if err := s.mgr.start(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started", "state": s.mgr.snapshot()})
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

	// Replay the current state so a freshly connected client sees the
	// capture it may have missed.
	writeSSE(w, flusher, event{Type: "state", State: s.mgr.snapshot()})

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, flusher, ev)
		case <-ticker.C:
			writeSSE(w, flusher, event{Type: "state", State: s.mgr.snapshot()})
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
	session := s.mgr.session
	s.mgr.mu.Unlock()
	if session == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "there is nothing to export"})
		return
	}
	if s.mgr.isRunning() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "stop the capture before exporting"})
		return
	}

	format := r.URL.Query().Get("format")
	switch format {
	case "json":
		data, err := report.JSON(session)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wyrm-report.json")
		_, _ = w.Write(data)
	case "html":
		page, err := report.HTML(session)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=wyrm-report.html")
		_, _ = io.WriteString(w, page)
	case "text", "":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=wyrm-report.txt")
		_, _ = io.WriteString(w, report.Text(session))
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown format"})
	}
}

// Run executes the gui subcommand and blocks until interrupted.
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wyrm gui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8788", "address to listen on")
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
		fmt.Fprintf(stderr, "wyrm gui: %v\n", err)
		return ExitError
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		if isAddrInUse(err) {
			url := browserURL(*listen)
			fmt.Fprintf(stdout, "wyrm gui is already running at %s\n", url)
			if *openBrowser && !*noOpen {
				launchBrowser(url)
			}
			return ExitOK
		}
		fmt.Fprintf(stderr, "wyrm gui: listening on %s: %v\n", *listen, err)
		return ExitError
	}

	url := browserURL(ln.Addr().String())

	fmt.Fprintf(stdout, "wyrm gui running at %s\n", url)
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
			fmt.Fprintf(stderr, "wyrm gui: %v\n", err)
			return ExitError
		}
		return ExitOK
	}
}

// launchBrowser opens the given URL in the first available browser.
func launchBrowser(url string) {
	for _, candidate := range []string{"firefox", "firefox-esr", "xdg-open", "chromium", "chromium-browser", "google-chrome"} {
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

// browserURL turns a listen address into a browser URL, mapping wildcard
// addresses back to the loopback.
func browserURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// isAddrInUse reports whether the error means the address is already bound.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
