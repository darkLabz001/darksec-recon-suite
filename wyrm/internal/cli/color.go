package cli

import (
	"strings"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
)

// ANSI colour codes used by the coloured output.
const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiOrange = "\033[38;5;208m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiGrey   = "\033[90m"
)

// severityColor returns the colour code of a severity.
func severityColor(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return ansiRed
	case audit.SeverityHigh:
		return ansiOrange
	case audit.SeverityMedium:
		return ansiYellow
	case audit.SeverityLow:
		return ansiBlue
	default:
		return ansiGrey
	}
}

// colorize wraps a string in a colour code unless the colours are switched
// off.
func colorize(noColor bool, text, code string) string {
	if noColor || code == "" {
		return text
	}
	return code + strings.ToUpper(text) + ansiReset
}
