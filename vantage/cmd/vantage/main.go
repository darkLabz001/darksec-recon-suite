// Command vantage is a fast, dependency free port scanner with service
// detection.
package main

import (
	"os"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
