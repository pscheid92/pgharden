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

func (f *fakeCheck) ID() string                  { return f.id }
func (f *fakeCheck) Requirements() CheckRequirements { return f.reqs }
func (f *fakeCheck) Run(_ context.Context, _ *Environment) (*CheckResult, error) {
	return f.res, f.err
}

func setupRunner(checks []Check, env *Environment) *Runner {
	registryMu.Lock()
	origRegistry := registry
	registry = make(map[string]Check)
	for _, c := range checks {
		registry[c.ID()] = c
	}
	registryMu.Unlock()

	r := &Runner{Env: env}

	// Restore after test — caller should defer this.
	// For simplicity, we restore in each test.
	_ = origRegistry
	return r
}

func restoreRegistry(orig map[string]Check) {
	registryMu.Lock()
	registry = orig
	registryMu.Unlock()
}

func TestRunnerIncludeFilter(t *testing.T) {
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	pass := &CheckResult{Status: StatusPass}
	Register(&fakeCheck{id: "1.1", res: pass})
	Register(&fakeCheck{id: "1.2", res: pass})
	Register(&fakeCheck{id: "2.1", res: pass})

	env := &Environment{PGVersion: 16, Commands: map[string]bool{}}
	r := &Runner{Env: env, IncludeChecks: []string{"1.1"}}
	results := r.RunAll(context.Background())

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].CheckID != "1.1" {
		t.Errorf("got check %s, want 1.1", results[0].CheckID)
	}
}

func TestRunnerExcludeFilter(t *testing.T) {
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	pass := &CheckResult{Status: StatusPass}
	Register(&fakeCheck{id: "1.1", res: pass})
	Register(&fakeCheck{id: "1.2", res: pass})

	env := &Environment{PGVersion: 16, Commands: map[string]bool{}}
	r := &Runner{Env: env, ExcludeChecks: []string{"1.1"}}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].CheckID != "1.2" {
		t.Errorf("expected only check 1.2, got %v", results)
	}
}

func TestRunnerSectionFilter(t *testing.T) {
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	pass := &CheckResult{Status: StatusPass}
	Register(&fakeCheck{id: "1.1", res: pass})
	Register(&fakeCheck{id: "2.1", res: pass})
	Register(&fakeCheck{id: "2.2", res: pass})

	env := &Environment{PGVersion: 16, Commands: map[string]bool{}}
	r := &Runner{Env: env, IncludeSection: "2"}
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
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	Register(&fakeCheck{
		id:   "1.1",
		reqs: CheckRequirements{MinPGVersion: 16},
		res:  &CheckResult{Status: StatusPass},
	})

	env := &Environment{PGVersion: 14, Commands: map[string]bool{}}
	r := &Runner{Env: env}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped, got %v", results)
	}
}

func TestRunnerSkipSuperuser(t *testing.T) {
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	Register(&fakeCheck{
		id:   "1.1",
		reqs: CheckRequirements{Superuser: true},
		res:  &CheckResult{Status: StatusPass},
	})

	env := &Environment{PGVersion: 16, Commands: map[string]bool{}}
	r := &Runner{Env: env}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for non-superuser, got %v", results)
	}
}

func TestRunnerSkipFilesystem(t *testing.T) {
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	Register(&fakeCheck{
		id:   "1.1",
		reqs: CheckRequirements{Filesystem: true},
		res:  &CheckResult{Status: StatusPass},
	})

	env := &Environment{PGVersion: 16, HasFilesystem: false, Commands: map[string]bool{}}
	r := &Runner{Env: env}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for no filesystem, got %v", results)
	}
}

func TestRunnerSkipCommand(t *testing.T) {
	registryMu.Lock()
	orig := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer restoreRegistry(orig)

	Register(&fakeCheck{
		id:   "1.1",
		reqs: CheckRequirements{Commands: []string{"lsblk"}},
		res:  &CheckResult{Status: StatusPass},
	})

	env := &Environment{PGVersion: 16, Commands: map[string]bool{}}
	r := &Runner{Env: env}
	results := r.RunAll(context.Background())

	if len(results) != 1 || results[0].Result.Status != StatusSkipped {
		t.Errorf("expected skipped for missing command, got %v", results)
	}
}
