package runner

import (
	"context"
	"testing"

	"github.com/pscheid92/pgharden/internal/domain"
)

// fakeCheck is a minimal Check for testing the runner.
type fakeCheck struct {
	id   string
	ref  *domain.Reference
	reqs domain.CheckRequirements
	res  *domain.CheckResult
	err  error
}

func (f *fakeCheck) ID() string                    { return f.id }
func (f *fakeCheck) Reference() *domain.Reference  { return f.ref }
func (f *fakeCheck) Requirements() domain.CheckRequirements { return f.reqs }
func (f *fakeCheck) Run(_ context.Context, _ *domain.Environment) (*domain.CheckResult, error) {
	return f.res, f.err
}

func TestRunnerIncludeFilter(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", res: pass},
		&fakeCheck{id: "1.2", res: pass},
		&fakeCheck{id: "2.1", res: pass},
	}

	r := &Runner{
		Checks:        checks,
		Env:           &domain.Environment{PGVersion: 16, Commands: map[string]bool{}},
		IncludeChecks: []string{"1.1"},
	}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].CheckID != "1.1" {
		t.Errorf("got check %s, want 1.1", results[0].CheckID)
	}
}

func TestRunnerExcludeFilter(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", res: pass},
		&fakeCheck{id: "1.2", res: pass},
	}

	r := &Runner{
		Checks:        checks,
		Env:           &domain.Environment{PGVersion: 16, Commands: map[string]bool{}},
		ExcludeChecks: []string{"1.1"},
	}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].CheckID != "1.2" {
		t.Errorf("expected only check 1.2, got %v", results)
	}
}

func TestRunnerSectionFilter(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", res: pass},
		&fakeCheck{id: "2.1", res: pass},
		&fakeCheck{id: "2.2", res: pass},
	}

	r := &Runner{
		Checks:         checks,
		Env:            &domain.Environment{PGVersion: 16, Commands: map[string]bool{}},
		IncludeSection: "2",
	}
	results := r.RunAll(context.Background())

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, rr := range results {
		if rr.CheckID != "2.1" && rr.CheckID != "2.2" {
			t.Errorf("unexpected check: %s", rr.CheckID)
		}
	}
}

func TestRunnerSkipVersion(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{MinPGVersion: 16}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 14, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusSkipped {
		t.Errorf("expected skipped, got %v", results)
	}
}

func TestRunnerSkipSuperuser(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{Superuser: true}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusSkipped {
		t.Errorf("expected skipped for non-superuser, got %v", results)
	}
}

func TestRunnerSkipFilesystem(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{Filesystem: true}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, HasFilesystem: false, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusSkipped {
		t.Errorf("expected skipped for no filesystem, got %v", results)
	}
}

func TestRunnerSkipCommand(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{Commands: []string{"lsblk"}}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusSkipped {
		t.Errorf("expected skipped for missing command, got %v", results)
	}
}

func TestRunnerSkipPGMonitor(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{PGMonitor: true}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusSkipped {
		t.Errorf("expected skipped for non-pg_monitor, got %v", results)
	}
}

func TestRunnerPGMonitorSatisfiedBySuperuser(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{PGMonitor: true}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, IsSuperuser: true, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusPass {
		t.Errorf("expected PASS (superuser satisfies pg_monitor), got %v", results)
	}
}

func TestRunnerSuperuserSatisfiedByRDS(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{Superuser: true}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, IsRDSSuperuser: true, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusPass {
		t.Errorf("expected PASS (RDS superuser satisfies superuser req), got %v", results)
	}
}

func TestRunnerCommandAvailable(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{Commands: []string{"systemctl"}}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{"systemctl": true}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusPass {
		t.Errorf("expected PASS when command is available, got %v", results)
	}
}

func TestRunnerAllRequirementsMet(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{
			MinPGVersion: 15,
			Superuser:    true,
			Filesystem:   true,
			Commands:     []string{"ps"},
		}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{
		PGVersion:     16,
		IsSuperuser:   true,
		HasFilesystem: true,
		Commands:      map[string]bool{"ps": true},
	}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusPass {
		t.Errorf("expected PASS when all requirements met, got %v", results)
	}
}

func TestRunnerCheckErrorBecomesCritical(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", err: context.DeadlineExceeded},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rr := results[0]
	if rr.Result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for check error, got %s", rr.Result.Status)
	}
	if rr.Result.Severity != domain.SeverityCritical {
		t.Errorf("expected CRITICAL severity for check error, got %s", rr.Result.Severity)
	}
}

func TestRunnerPermissionDeniedBecomesSkipped(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", err: domain.ErrPermissionDenied},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rr := results[0]
	if rr.Result.Status != domain.StatusSkipped {
		t.Errorf("expected SKIPPED for permission denied, got %s", rr.Result.Status)
	}
	if rr.Result.SkipReason == "" {
		t.Error("expected skip reason to be set")
	}
}

func TestRunnerSkipPlatform(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}, res: pass},
		&fakeCheck{id: "1.2", reqs: domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}, res: pass},
		&fakeCheck{id: "1.3", res: pass}, // no skip
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Platform: domain.PlatformRDS, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Result.Status != domain.StatusSkipped {
		t.Errorf("check 1.1: expected SKIPPED on RDS (NonBareMetal), got %s", results[0].Result.Status)
	}
	if results[1].Result.Status != domain.StatusSkipped {
		t.Errorf("check 1.2: expected SKIPPED on RDS (ManagedCloud), got %s", results[1].Result.Status)
	}
	if results[2].Result.Status != domain.StatusPass {
		t.Errorf("check 1.3: expected PASS (no skip), got %s", results[2].Result.Status)
	}
}

func TestRunnerPlatformNotSkippedOnBareMetal(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}, res: pass},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Platform: domain.PlatformBareMetal, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusPass {
		t.Errorf("expected PASS on bare-metal, got %v", results)
	}
}

func TestRunnerSourceFilter(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", ref: domain.CISRef("1.1"), res: pass},
		&fakeCheck{id: "1.2", res: pass}, // no reference
		&fakeCheck{id: "1.3", ref: &domain.Reference{Source: "OWASP", ID: "A1"}, res: pass},
	}

	r := &Runner{
		Checks:        checks,
		Env:           &domain.Environment{PGVersion: 16, Commands: map[string]bool{}},
		IncludeSource: "cis",
	}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].CheckID != "1.1" {
		t.Errorf("got check %s, want 1.1", results[0].CheckID)
	}
}

func TestRunnerSourceFilterCaseInsensitive(t *testing.T) {
	pass := &domain.CheckResult{Status: domain.StatusPass}
	checks := []domain.Check{
		&fakeCheck{id: "1.1", ref: domain.CISRef("1.1"), res: pass},
	}

	r := &Runner{
		Checks:        checks,
		Env:           &domain.Environment{PGVersion: 16, Commands: map[string]bool{}},
		IncludeSource: "CIS",
	}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1 (case-insensitive match)", len(results))
	}
}

func TestRunnerResultIncludesReference(t *testing.T) {
	ref := domain.CISRef("1.1")
	checks := []domain.Check{
		&fakeCheck{id: "1.1", ref: ref, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Reference != ref {
		t.Errorf("expected reference to be passed through, got %v", results[0].Reference)
	}
}

func TestRunnerVersionMet(t *testing.T) {
	checks := []domain.Check{
		&fakeCheck{id: "1.1", reqs: domain.CheckRequirements{MinPGVersion: 15}, res: &domain.CheckResult{Status: domain.StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &domain.Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != domain.StatusPass {
		t.Errorf("expected PASS when PG version meets requirement, got %v", results)
	}
}
