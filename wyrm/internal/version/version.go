// Package version exposes build information about the auditor.
package version

import (
	"fmt"
	"runtime"
)

// Version is the semantic version of the build. It is overridden at link
// time with -ldflags "-X github.com/darkLabz001/darksec-recon-suite/wyrm/internal/version.Version=...".
var Version = "1.0.0"

// Commit is the git revision of the build, set at link time.
var Commit = "unknown"

// Date is the build date, set at link time.
var Date = "unknown"

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build information.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String renders a human readable build banner.
func String() string {
	i := Get()
	return fmt.Sprintf("wyrm %s (%s) %s %s", i.Version, i.Commit, i.GoVersion, i.Platform)
}
