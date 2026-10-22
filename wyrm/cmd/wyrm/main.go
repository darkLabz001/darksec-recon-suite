// Command wyrm is a WPA3 and WPA2 wireless security auditor.
package main

import (
	"os"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
