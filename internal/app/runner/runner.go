package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pscheid92/pgharden/internal/domain"
)

type Runner struct {
	Env *domain.Environment

	Checks         []domain.Check // The checks to run.
	IncludeChecks  []string       // If non-empty, only run these check IDs.
	ExcludeChecks  []string       // Skip these check IDs.
	IncludeSection string         // If set, only run checks in this section (e.g., "3").
	IncludeSource  string         // If set, only run checks from this source (e.g., "cis").
}

func (r *Runner) RunAll(ctx context.Context) []domain.RunResult {
	checks := r.Checks
	results := make([]domain.RunResult, 0, len(checks))

	for _, c := range checks {
		if r.shouldSkip(c) {
			continue
		}

		result := r.runOne(ctx, c)
		results = append(results, result)
	}
	return results
}

func (r *Runner) shouldSkip(c domain.Check) bool {
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
		if domain.SectionID(id) != r.IncludeSection {
			return true
		}
	}

	// Source filter
	if r.IncludeSource != "" {
		ref := c.Reference()
		if ref == nil || !strings.Contains(strings.ToLower(ref.Source), strings.ToLower(r.IncludeSource)) {
			return true
		}
	}

	return false
}

func (r *Runner) runOne(ctx context.Context, c domain.Check) domain.RunResult {
	id := c.ID()
	ref := c.Reference()
	requirements := c.Requirements()

	if len(requirements.SkipPlatforms) > 0 && slices.Contains(requirements.SkipPlatforms, r.Env.Platform) {
		return domain.RunResult{
			CheckID:   id,
			Reference: ref,
			Result: &domain.CheckResult{
				Status:     domain.StatusSkipped,
				SkipReason: fmt.Sprintf("Not applicable on platform: %s", r.Env.Platform),
			},
		}
	}

	if requirements.MinPGVersion > 0 && r.Env.PGVersion < requirements.MinPGVersion {
		return domain.RunResult{
			CheckID:   id,
			Reference: ref,
			Result: &domain.CheckResult{
				Status:     domain.StatusSkipped,
				SkipReason: fmt.Sprintf("Requires PostgreSQL %d+, running %d", requirements.MinPGVersion, r.Env.PGVersion),
			},
		}
	}

	if requirements.Superuser && !r.Env.IsSuperuser && !r.Env.IsRDSSuperuser {
		return domain.RunResult{
			CheckID:   id,
			Reference: ref,
			Result: &domain.CheckResult{
				Status:     domain.StatusSkipped,
				SkipReason: "Requires superuser privileges",
			},
		}
	}

	if requirements.PGMonitor && !r.Env.IsPGMonitor && !r.Env.IsSuperuser {
		return domain.RunResult{
			CheckID:   id,
			Reference: ref,
			Result: &domain.CheckResult{
				Status:     domain.StatusSkipped,
				SkipReason: "Requires pg_monitor or superuser privileges",
			},
		}
	}

	if requirements.Filesystem && !r.Env.HasFilesystem {
		return domain.RunResult{
			CheckID:   id,
			Reference: ref,
			Result: &domain.CheckResult{
				Status:     domain.StatusSkipped,
				SkipReason: "Requires filesystem access (not available in this environment)",
			},
		}
	}

	for _, cmd := range requirements.Commands {
		if !r.Env.Commands[cmd] {
			return domain.RunResult{
				CheckID: id,
				Result: &domain.CheckResult{
					Status:     domain.StatusSkipped,
					SkipReason: fmt.Sprintf("Required command not available: %s", cmd),
				},
			}
		}
	}

	result, err := c.Run(ctx, r.Env)
	if errors.Is(err, domain.ErrPermissionDenied) {
		return domain.RunResult{
			CheckID:   id,
			Reference: ref,
			Result:    &domain.CheckResult{Status: domain.StatusSkipped, SkipReason: "Insufficient privileges"},
		}
	}
	if err != nil {
		result = &domain.CheckResult{Status: domain.StatusFail, Severity: domain.SeverityCritical}
		result.Critical(err.Error())
	}
	return domain.RunResult{CheckID: id, Reference: ref, Result: result}
}
