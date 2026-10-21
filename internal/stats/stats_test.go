package stats

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewDisablesProgressForNonTerminals(t *testing.T) {
	r := New(&bytes.Buffer{}, false)
	if r.enabled {
		t.Error("the reporter is enabled for a non terminal writer")
	}
}

func TestAddCountsStates(t *testing.T) {
	r := New(&bytes.Buffer{}, true)
	r.SetTotal(10)
	r.Add("open")
	r.Add("closed")
	r.Add("closed")
	r.Add("filtered")
	r.Add("something else")

	total, completed, open, closed, filtered := r.Snapshot()
	if total != 10 {
		t.Errorf("the total is %d, want 10", total)
	}
	if completed != 5 {
		t.Errorf("the completed count is %d, want 5", completed)
	}
	if open != 1 {
		t.Errorf("the open count is %d, want 1", open)
	}
	if closed != 2 {
		t.Errorf("the closed count is %d, want 2", closed)
	}
	if filtered != 2 {
		t.Errorf("the filtered count is %d, want 2", filtered)
	}
}

func TestSummaryIsSilentWhenQuiet(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, true)
	r.Add("open")
	r.Summary()
	if buf.Len() != 0 {
		t.Errorf("the quiet reporter wrote %q", buf.String())
	}
}

func TestSummaryReportsTheOutcome(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, false)
	r.SetTotal(3)
	r.Add("open")
	r.Add("closed")
	r.Add("open")

	r.Summary()
	out := buf.String()
	for _, want := range []string{"Scan complete", "3 probes", "2 open", "1 closed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary %q does not contain %q", out, want)
		}
	}
}

func TestSummaryWarnsAboutIncompleteScans(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, false)
	r.SetTotal(10)
	r.Add("open")

	r.Summary()
	out := buf.String()
	if !strings.Contains(out, "9 of 10 probes were not completed") {
		t.Errorf("the summary %q does not warn about the missing probes", out)
	}
}

func TestProgressBar(t *testing.T) {
	r := New(&bytes.Buffer{}, true)

	empty := r.progressBar()
	if len(empty) != 26 {
		t.Errorf("the empty bar is %d characters, want 26", len(empty))
	}
	if !strings.HasPrefix(empty, "[") || !strings.HasSuffix(empty, "]") {
		t.Errorf("the bar %q is not bracketed", empty)
	}

	r.SetTotal(10)
	r.Add("open")
	half := r.progressBar()
	if !strings.HasPrefix(half, "[=") {
		t.Errorf("the bar %q does not show progress", half)
	}

	r.SetTotal(1)
	for i := 0; i < 5; i++ {
		r.Add("open")
	}
	full := r.progressBar()
	if strings.Contains(full, " ") {
		t.Errorf("the full bar %q still has empty cells", full)
	}
}

func TestFormatRate(t *testing.T) {
	cases := []struct {
		rate float64
		want string
	}{
		{0, "0.00"},
		{0.5, "0.50"},
		{12, "12"},
		{1500, "1.5k"},
		{25000, "25.0k"},
	}
	for _, c := range cases {
		if got := formatRate(c.rate); got != c.want {
			t.Errorf("formatRate(%v) = %q, want %q", c.rate, got, c.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "--"},
		{-time.Second, "--"},
		{250 * time.Millisecond, "250ms"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m30s"},
		{2 * time.Hour, "2h0m"},
	}
	for _, c := range cases {
		if got := formatDuration(c.d); got != c.want {
			t.Errorf("formatDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestStartStopsWhenTheScanFinishes(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, false)
	r.SetTotal(1)
	r.Add("open")

	done := make(chan struct{})
	r.Start(done)
	close(done)

	// The reporter is disabled for a buffer, so nothing is drawn.
	time.Sleep(50 * time.Millisecond)
	if buf.Len() != 0 {
		t.Errorf("the reporter drew %q for a non terminal writer", buf.String())
	}
}
