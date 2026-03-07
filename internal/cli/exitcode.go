package cli

import "github.com/pgharden/pgharden/internal/report"

// Exit codes returned by the CLI.
const (
	ExitOK               = 0 // All checks passed.
	ExitCriticalFindings = 1 // One or more critical findings.
	ExitFailedChecks     = 2 // Non-critical check failures.
	ExitError            = 3 // Runtime error (connection, config, etc.).
)

func exitCodeFromReport(rpt *report.Report) int {
	if rpt.Summary.BySeverity["CRITICAL"] > 0 {
		return ExitCriticalFindings
	}
	if rpt.Summary.Failed > 0 {
		return ExitFailedChecks
	}
	return ExitOK
}
