// Package stats renders live progress information during a scan.
package stats

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Reporter tracks scan progress and renders it to a terminal.
type Reporter struct {
	mu sync.Mutex

	out     io.Writer
	enabled bool
	quiet   bool

	total     int64
	completed int64
	open      int64
	closed    int64
	filtered  int64

	start    time.Time
	lastDraw time.Time
}

// New returns a reporter. When quiet is false the reporter prints a
// progress line, provided the output is a terminal.
func New(out io.Writer, quiet bool) *Reporter {
	return &Reporter{
		out:     out,
		enabled: isTerminal(out),
		quiet:   quiet,
		start:   time.Now(),
	}
}

// SetTotal sets the number of probes the scan expects to perform.
func (r *Reporter) SetTotal(n int64) {
	r.mu.Lock()
	r.total = n
	r.mu.Unlock()
}

// Add advances the counters for a single probe.
func (r *Reporter) Add(state string) {
	r.mu.Lock()
	r.completed++
	switch state {
	case "open":
		r.open++
	case "closed":
		r.closed++
	default:
		r.filtered++
	}
	r.mu.Unlock()
}

// Snapshot returns a copy of the current counters.
func (r *Reporter) Snapshot() (total, completed, open, closed, filtered int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total, r.completed, r.open, r.closed, r.filtered
}

// Start begins rendering the progress display.
func (r *Reporter) Start(ctxDone <-chan struct{}) {
	if !r.enabled || r.quiet {
		return
	}
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctxDone:
				r.draw(true)
				return
			case <-ticker.C:
				r.draw(false)
			}
		}
	}()
}

// draw renders the progress line.
func (r *Reporter) draw(final bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !final && time.Since(r.lastDraw) < 150*time.Millisecond {
		return
	}
	r.lastDraw = time.Now()

	elapsed := time.Since(r.start)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(r.completed) / elapsed.Seconds()
	}

	eta := time.Duration(0)
	if rate > 0 && r.total > r.completed {
		remaining := float64(r.total-r.completed) / rate
		eta = time.Duration(remaining * float64(time.Second))
	}

	bar := r.progressBar()

	fmt.Fprintf(r.out, "\r%s %d/%d open=%d closed=%d filtered=%d %s/s eta=%s   ",
		bar, r.completed, r.total, r.open, r.closed, r.filtered,
		formatRate(rate), formatDuration(eta))
	if final {
		fmt.Fprintln(r.out)
	}
}

// progressBar renders a simple textual progress bar.
func (r *Reporter) progressBar() string {
	const width = 24
	if r.total <= 0 {
		return "[" + strings.Repeat(" ", width) + "]"
	}
	filled := int(float64(r.completed) / float64(r.total) * width)
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("=", filled) + strings.Repeat(" ", width-filled) + "]"
}

// Summary prints a final report of the scan.
func (r *Reporter) Summary() {
	if r.quiet {
		return
	}
	total, completed, open, closed, filtered := r.Snapshot()
	elapsed := time.Since(r.start)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(completed) / elapsed.Seconds()
	}
	fmt.Fprintf(r.out, "\nScan complete: %d probes in %s (%.0f/s), %d open, %d closed, %d filtered\n",
		completed, elapsed.Round(time.Millisecond), rate, open, closed, filtered)
	if total > 0 && completed < total {
		fmt.Fprintf(r.out, "Warning: %d of %d probes were not completed\n", total-completed, total)
	}
}

func formatRate(rate float64) string {
	switch {
	case rate >= 1000:
		return fmt.Sprintf("%.1fk", rate/1000)
	case rate >= 1:
		return fmt.Sprintf("%.0f", rate)
	default:
		return fmt.Sprintf("%.2f", rate)
	}
}

func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "--"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// isTerminal reports whether the writer is an interactive terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
