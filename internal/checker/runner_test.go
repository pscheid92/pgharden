package checker

import (
	"context"
	"testing"
)

// fakeCheck is a minimal Check for testing the runner.
type fakeCheck struct {
	id   string
	reqs CheckRequirements
	res  *CheckResult
	err  error
}

func (f *fakeCheck) ID() string                                                  { return f.id }
func (f *fakeCheck) Requirements() CheckRequirements                             { return f.reqs }
func (f *fakeCheck) Run(_ context.Context, _ *Environment) (*CheckResult, error) { return f.res, f.err }

func TestRunnerIncludeFilter(t *testing.T) {
	pass := &CheckResult{Status: StatusPass}
	checks := []Check{
		&fakeCheck{id: "1.1", res: pass},
		&fakeCheck{id: "1.2", res: pass},
		&fakeCheck{id: "2.1", res: pass},
	}

	r := &Runner{
		Checks:        checks,
		Env:           &Environment{PGVersion: 16, Commands: map[string]bool{}},
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
	pass := &CheckResult{Status: StatusPass}
	checks := []Check{
		&fakeCheck{id: "1.1", res: pass},
		&fakeCheck{id: "1.2", res: pass},
	}

	r := &Runner{
		Checks:        checks,
		Env:           &Environment{PGVersion: 16, Commands: map[string]bool{}},
		ExcludeChecks: []string{"1.1"},
	}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].CheckID != "1.2" {
		t.Errorf("expected only check 1.2, got %v", results)
	}
}

func TestRunnerSectionFilter(t *testing.T) {
	pass := &CheckResult{Status: StatusPass}
	checks := []Check{
		&fakeCheck{id: "1.1", res: pass},
		&fakeCheck{id: "2.1", res: pass},
		&fakeCheck{id: "2.2", res: pass},
	}

	r := &Runner{
		Checks:         checks,
		Env:            &Environment{PGVersion: 16, Commands: map[string]bool{}},
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
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{MinPGVersion: 16}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 14, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped, got %v", results)
	}
}

func TestRunnerSkipSuperuser(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{Superuser: true}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for non-superuser, got %v", results)
	}
}

func TestRunnerSkipFilesystem(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{Filesystem: true}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, HasFilesystem: false, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for no filesystem, got %v", results)
	}
}

func TestRunnerSkipCommand(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{Commands: []string{"lsblk"}}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for missing command, got %v", results)
	}
}

func TestRunnerSkipPGMonitor(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{PGMonitor: true}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for non-pg_monitor, got %v", results)
	}
}

func TestRunnerPGMonitorSatisfiedBySuperuser(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{PGMonitor: true}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, IsSuperuser: true, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusPass {
		t.Errorf("expected PASS (superuser satisfies pg_monitor), got %v", results)
	}
}

func TestRunnerSuperuserSatisfiedByRDS(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{Superuser: true}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, IsRDSSuperuser: true, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusPass {
		t.Errorf("expected PASS (RDS superuser satisfies superuser req), got %v", results)
	}
}

func TestRunnerCommandAvailable(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{Commands: []string{"systemctl"}}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, Commands: map[string]bool{"systemctl": true}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusPass {
		t.Errorf("expected PASS when command is available, got %v", results)
	}
}

func TestRunnerAllRequirementsMet(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{
			MinPGVersion: 15,
			Superuser:    true,
			Filesystem:   true,
			Commands:     []string{"ps"},
		}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{
		PGVersion:     16,
		IsSuperuser:   true,
		HasFilesystem: true,
		Commands:      map[string]bool{"ps": true},
	}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusPass {
		t.Errorf("expected PASS when all requirements met, got %v", results)
	}
}

func TestRunnerCheckErrorBecomesCritical(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", err: context.DeadlineExceeded},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rr := results[0]
	if rr.Result.Status != StatusFail {
		t.Errorf("expected FAIL for check error, got %s", rr.Result.Status)
	}
	if rr.Result.Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity for check error, got %s", rr.Result.Severity)
	}
}

func TestRunnerVersionMet(t *testing.T) {
	checks := []Check{
		&fakeCheck{id: "1.1", reqs: CheckRequirements{MinPGVersion: 15}, res: &CheckResult{Status: StatusPass}},
	}

	r := &Runner{Checks: checks, Env: &Environment{PGVersion: 16, Commands: map[string]bool{}}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusPass {
		t.Errorf("expected PASS when PG version meets requirement, got %v", results)
	}
}
