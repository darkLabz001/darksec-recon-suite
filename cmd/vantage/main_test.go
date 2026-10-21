package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestMainRuns builds the binary and checks that it behaves.
//
// The scanner is exercised through the command line because that is the
// surface most users touch.
func TestMainRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("the test builds the binary")
	}

	if runtime.GOOS == "windows" {
		t.Skip("the test relies on a POSIX shell")
	}

	dir := t.TempDir()
	bin := dir + "/vantage"

	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("the build failed: %v\n%s", err, out)
	}

	t.Run("help", func(t *testing.T) {
		out, err := exec.Command(bin, "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("the binary failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Errorf("the help output does not contain a usage section: %q", out)
		}
	})

	t.Run("version", func(t *testing.T) {
		out, err := exec.Command(bin, "--version").CombinedOutput()
		if err != nil {
			t.Fatalf("the binary failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "vantage") {
			t.Errorf("the version output is %q", out)
		}
	})

	t.Run("usage error", func(t *testing.T) {
		cmd := exec.Command(bin)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("the binary accepted an empty command line: %q", out)
		}
		if !strings.Contains(string(out), "no targets") {
			t.Errorf("the error output is %q", out)
		}
	})
}
