package scanner

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"

	"github.com/pscheid92/pgharden/internal/app/report"
	"github.com/pscheid92/pgharden/internal/domain"
)

func newPgxMock(t *testing.T) pgxmock.PgxConnIface {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock
}

func TestScan_EmptySection(t *testing.T) {
	mock := newPgxMock(t)
	env := &domain.Environment{
		DB:        mock,
		PGVersion: 16,
		Platform:  domain.PlatformBareMetal,
	}

	result := Scan(context.Background(), env, Options{
		IncludeChecks: []string{"0.0.0"}, // nonexistent — no checks run
	})

	if result.Report == nil {
		t.Fatal("Scan returned nil report")
	}
	if result.Report.Summary.Total != 0 {
		t.Errorf("expected 0 checks for nonexistent section, got %d", result.Report.Summary.Total)
	}
	if result.ExitCode != ExitOK {
		t.Errorf("expected ExitOK, got %d", result.ExitCode)
	}
}

func TestScan_SectionFilter(t *testing.T) {
	mock := newPgxMock(t)
	env := &domain.Environment{
		DB:        mock,
		PGVersion: 16,
		Platform:  domain.PlatformBareMetal,
	}

	result := Scan(context.Background(), env, Options{
		IncludeSection: "8",
	})

	if result.Report.Summary.Total == 0 {
		t.Fatal("expected section 8 checks to run")
	}
	for _, cat := range result.Report.Categories {
		if cat.ID != "8" {
			t.Errorf("expected only section 8, got section %s", cat.ID)
		}
	}
}

func TestScan_ExitCodeReflectsFindings(t *testing.T) {
	mock := newPgxMock(t)
	env := &domain.Environment{
		DB:        mock,
		PGVersion: 16,
		Platform:  domain.PlatformBareMetal,
	}

	// 1.4.3 queries data_checksums — "off" produces a FAIL
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("data_checksums").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))

	result := Scan(context.Background(), env, Options{
		IncludeChecks: []string{"1.4.3"},
	})

	if result.ExitCode != ExitFailedChecks {
		t.Errorf("expected ExitFailedChecks (%d), got %d", ExitFailedChecks, result.ExitCode)
	}
}

// --- ExitCodeFromReport ---

func TestExitCodeFromReport_AllPassed(t *testing.T) {
	rpt := &report.Report{
		Summary: report.Summary{
			Total:      5,
			Passed:     5,
			BySeverity: map[string]int{},
		},
	}
	if code := ExitCodeFromReport(rpt); code != ExitOK {
		t.Errorf("expected ExitOK (%d), got %d", ExitOK, code)
	}
}

func TestExitCodeFromReport_CriticalFinding(t *testing.T) {
	rpt := &report.Report{
		Summary: report.Summary{
			Total:      5,
			Failed:     1,
			BySeverity: map[string]int{"CRITICAL": 1},
		},
	}
	if code := ExitCodeFromReport(rpt); code != ExitCriticalFindings {
		t.Errorf("expected ExitCriticalFindings (%d), got %d", ExitCriticalFindings, code)
	}
}

func TestExitCodeFromReport_NonCriticalFailure(t *testing.T) {
	rpt := &report.Report{
		Summary: report.Summary{
			Total:      5,
			Failed:     2,
			BySeverity: map[string]int{"WARNING": 2},
		},
	}
	if code := ExitCodeFromReport(rpt); code != ExitFailedChecks {
		t.Errorf("expected ExitFailedChecks (%d), got %d", ExitFailedChecks, code)
	}
}

func TestExitCodeFromReport_CriticalTakesPrecedence(t *testing.T) {
	rpt := &report.Report{
		Summary: report.Summary{
			Total:      10,
			Failed:     3,
			BySeverity: map[string]int{"CRITICAL": 1, "WARNING": 2},
		},
	}
	if code := ExitCodeFromReport(rpt); code != ExitCriticalFindings {
		t.Errorf("expected ExitCriticalFindings (%d) over ExitFailedChecks, got %d", ExitCriticalFindings, code)
	}
}

func TestExitCodeFromReport_SkippedAndManualOnly(t *testing.T) {
	rpt := &report.Report{
		Summary: report.Summary{
			Total:      5,
			Skipped:    3,
			Manual:     2,
			BySeverity: map[string]int{},
		},
	}
	if code := ExitCodeFromReport(rpt); code != ExitOK {
		t.Errorf("expected ExitOK for skipped+manual only, got %d", code)
	}
}
