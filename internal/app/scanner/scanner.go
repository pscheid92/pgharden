package scanner

import (
	"context"
	"log/slog"

	"github.com/pgharden/pgharden/internal/app/checks"
	"github.com/pgharden/pgharden/internal/app/report"
	"github.com/pgharden/pgharden/internal/app/runner"
	"github.com/pgharden/pgharden/internal/domain"
)

const (
	ExitOK               = 0 // All checks passed.
	ExitCriticalFindings = 1 // One or more critical findings.
	ExitFailedChecks     = 2 // Non-critical check failures.
)

type Options struct {
	IncludeChecks  []string
	ExcludeChecks  []string
	IncludeSection string
	Meta           report.Metadata
}

type Result struct {
	Report   *report.Report
	ExitCode int
}

func Scan(ctx context.Context, env *domain.Environment, opts Options) *Result {
	allChecks := checks.All()

	r := &runner.Runner{
		Checks:         allChecks,
		Env:            env,
		IncludeChecks:  opts.IncludeChecks,
		ExcludeChecks:  opts.ExcludeChecks,
		IncludeSection: opts.IncludeSection,
	}

	slog.Info("running checks", "count", len(allChecks))
	results := r.RunAll(ctx)

	rpt := report.Build(results, env, opts.Meta)
	return &Result{Report: rpt, ExitCode: ExitCodeFromReport(rpt)}
}

func ExitCodeFromReport(rpt *report.Report) int {
	if rpt.Summary.BySeverity["CRITICAL"] > 0 {
		return ExitCriticalFindings
	}
	if rpt.Summary.Failed > 0 {
		return ExitFailedChecks
	}
	return ExitOK
}
