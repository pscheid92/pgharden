package report

import (
	"fmt"
	"testing"

	"github.com/pgharden/pgharden/internal/checker"
)

func TestBuildSummaryCounts(t *testing.T) {
	results := []checker.RunResult{
		{CheckID: "1.1", Result: &checker.CheckResult{Status: checker.StatusPass, Severity: checker.SeverityInfo}},
		{CheckID: "1.2", Result: &checker.CheckResult{Status: checker.StatusFail, Severity: checker.SeverityWarning}},
		{CheckID: "1.3", Result: &checker.CheckResult{Status: checker.StatusFail, Severity: checker.SeverityCritical}},
		{CheckID: "1.4", Result: &checker.CheckResult{Status: checker.StatusSkipped, SkipReason: "no access"}},
		{CheckID: "1.5", Result: &checker.CheckResult{Status: checker.StatusManual, Severity: checker.SeverityInfo}},
		{CheckID: "2.1", Err: fmt.Errorf("query failed")},
	}

	rpt := Build(results, nil, Metadata{}, "en_US")

	if rpt.Summary.Total != 6 {
		t.Errorf("Total = %d, want 6", rpt.Summary.Total)
	}
	if rpt.Summary.Passed != 1 {
		t.Errorf("Passed = %d, want 1", rpt.Summary.Passed)
	}
	// Failed includes the error result + 2 fail results
	if rpt.Summary.Failed != 3 {
		t.Errorf("Failed = %d, want 3", rpt.Summary.Failed)
	}
	if rpt.Summary.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", rpt.Summary.Skipped)
	}
	if rpt.Summary.Manual != 1 {
		t.Errorf("Manual = %d, want 1", rpt.Summary.Manual)
	}
}

func TestBuildSectionGrouping(t *testing.T) {
	results := []checker.RunResult{
		{CheckID: "1.1", Result: &checker.CheckResult{Status: checker.StatusPass}},
		{CheckID: "1.2", Result: &checker.CheckResult{Status: checker.StatusPass}},
		{CheckID: "2.1", Result: &checker.CheckResult{Status: checker.StatusPass}},
		{CheckID: "3.1.2", Result: &checker.CheckResult{Status: checker.StatusPass}},
	}

	rpt := Build(results, nil, Metadata{}, "en_US")

	if len(rpt.Categories) != 3 {
		t.Fatalf("got %d categories, want 3", len(rpt.Categories))
	}
	if rpt.Categories[0].ID != "1" {
		t.Errorf("first category ID = %q, want 1", rpt.Categories[0].ID)
	}
	if len(rpt.Categories[0].Checks) != 2 {
		t.Errorf("section 1 has %d checks, want 2", len(rpt.Categories[0].Checks))
	}
}

func TestBuildBySeverity(t *testing.T) {
	results := []checker.RunResult{
		{CheckID: "1.1", Result: &checker.CheckResult{Status: checker.StatusFail, Severity: checker.SeverityCritical}},
		{CheckID: "1.2", Result: &checker.CheckResult{Status: checker.StatusFail, Severity: checker.SeverityCritical}},
		{CheckID: "1.3", Result: &checker.CheckResult{Status: checker.StatusFail, Severity: checker.SeverityWarning}},
	}

	rpt := Build(results, nil, Metadata{}, "en_US")

	if rpt.Summary.BySeverity["CRITICAL"] != 2 {
		t.Errorf("CRITICAL = %d, want 2", rpt.Summary.BySeverity["CRITICAL"])
	}
	if rpt.Summary.BySeverity["WARNING"] != 1 {
		t.Errorf("WARNING = %d, want 1", rpt.Summary.BySeverity["WARNING"])
	}
}
