package checker

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// Runner orchestrates check execution with filtering and skip logic.
type Runner struct {
	Checks         []Check  // The checks to run.
	Env            *Environment
	IncludeChecks  []string // If non-empty, only run these check IDs.
	ExcludeChecks  []string // Skip these check IDs.
	IncludeSection string   // If set, only run checks in this section (e.g., "3").
	MinSeverity    Severity // Only report checks at or above this severity.
}

// RunResult holds the outcome of a single check execution.
type RunResult struct {
	CheckID string
	Result  *CheckResult
	Err     error
}

// RunAll executes all checks, respecting filters and requirements.
func (r *Runner) RunAll(ctx context.Context) []RunResult {
	checks := r.Checks
	results := make([]RunResult, 0, len(checks))

	for _, c := range checks {
		if r.shouldSkip(c) {
			continue
		}

		result := r.runOne(ctx, c)
		results = append(results, result)
	}
	return results
}

func (r *Runner) shouldSkip(c Check) bool {
	id := c.ID()

	// Include filter
	if len(r.IncludeChecks) > 0 {
		found := slices.Contains(r.IncludeChecks, id)
		if !found {
			return true
		}
	}

	// Exclude filter
	if slices.Contains(r.ExcludeChecks, id) {
		return true
	}

	// Section filter
	if r.IncludeSection != "" {
		section := id
		if dot := strings.IndexByte(id, '.'); dot >= 0 {
			section = id[:dot]
		}
		if section != r.IncludeSection {
			return true
		}
	}

	return false
}

func (r *Runner) runOne(ctx context.Context, c Check) RunResult {
	id := c.ID()
	reqs := c.Requirements()

	// Check PG version requirement
	if reqs.MinPGVersion > 0 && r.Env.PGVersion < reqs.MinPGVersion {
		return RunResult{
			CheckID: id,
			Result: &CheckResult{
				Status:     StatusSkipped,
				SkipReason: fmt.Sprintf("Requires PostgreSQL %d+, running %d", reqs.MinPGVersion, r.Env.PGVersion),
			},
		}
	}

	// Check superuser requirement
	if reqs.Superuser && !r.Env.IsSuperuser && !r.Env.IsRDSSuperuser {
		return RunResult{
			CheckID: id,
			Result: &CheckResult{
				Status:     StatusSkipped,
				SkipReason: "Requires superuser privileges",
			},
		}
	}

	// Check pg_monitor requirement
	if reqs.PGMonitor && !r.Env.IsPGMonitor && !r.Env.IsSuperuser {
		return RunResult{
			CheckID: id,
			Result: &CheckResult{
				Status:     StatusSkipped,
				SkipReason: "Requires pg_monitor or superuser privileges",
			},
		}
	}

	// Check filesystem requirement
	if reqs.Filesystem && !r.Env.HasFilesystem {
		return RunResult{
			CheckID: id,
			Result: &CheckResult{
				Status:     StatusSkipped,
				SkipReason: "Requires filesystem access (not available in this environment)",
			},
		}
	}

	// Check command requirements
	for _, cmd := range reqs.Commands {
		if !r.Env.Commands[cmd] {
			return RunResult{
				CheckID: id,
				Result: &CheckResult{
					Status:     StatusSkipped,
					SkipReason: fmt.Sprintf("Required command not available: %s", cmd),
				},
			}
		}
	}

	// Run the check
	result, err := c.Run(ctx, r.Env)
	return RunResult{
		CheckID: id,
		Result:  result,
		Err:     err,
	}
}
