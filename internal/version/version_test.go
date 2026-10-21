package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Error("the version is empty")
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("the Go version is %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("the platform is %q", info.Platform)
	}
}

func TestString(t *testing.T) {
	s := String()
	if !strings.HasPrefix(s, "vantage ") {
		t.Errorf("the banner %q does not start with the program name", s)
	}
	if !strings.Contains(s, Version) {
		t.Errorf("the banner %q does not carry the version", s)
	}
}

func TestInfoFieldsArePopulated(t *testing.T) {
	// The commit and the date are set at link time and default to
	// placeholders.
	info := Get()
	if info.Commit == "" {
		t.Error("the commit is empty")
	}
	if info.Date == "" {
		t.Error("the date is empty")
	}
}
