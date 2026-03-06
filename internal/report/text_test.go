package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteText(t *testing.T) {
	rpt := &Report{
		Summary: Summary{Total: 3, Passed: 1, Failed: 1, Skipped: 1, BySeverity: map[string]int{"WARNING": 1}},
		Categories: []CategoryReport{
			{
				ID:    "1",
				Title: "Installation",
				Checks: []CheckReport{
					{ID: "1.1", Title: "Check One", Status: "PASS", Messages: []MsgEntry{{Level: "SUCCESS", Content: "All good"}}},
					{ID: "1.2", Title: "Check Two", Status: "FAIL", Severity: "WARNING", Messages: []MsgEntry{{Level: "FAILURE", Content: "Bad config"}}},
					{ID: "1.3", Title: "Check Three", Status: "SKIPPED", SkipReason: "No access"},
				},
			},
		},
	}

	t.Run("no_color", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteText(&buf, rpt, false); err != nil {
			t.Fatalf("WriteText: %v", err)
		}
		out := buf.String()

		if !strings.Contains(out, "[PASS]") {
			t.Error("missing [PASS] prefix")
		}
		if !strings.Contains(out, "[FAIL]") {
			t.Error("missing [FAIL] prefix")
		}
		if !strings.Contains(out, "[SKIP]") {
			t.Error("missing [SKIP] prefix")
		}
		if !strings.Contains(out, "1 passed") {
			t.Error("missing summary passed count")
		}
		if !strings.Contains(out, "1 failed") {
			t.Error("missing summary failed count")
		}
		if !strings.Contains(out, "=== 1: Installation ===") {
			t.Error("missing section header")
		}
		// No ANSI codes
		if strings.Contains(out, "\033[") {
			t.Error("found ANSI codes in no-color output")
		}
	})

	t.Run("with_color", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteText(&buf, rpt, true); err != nil {
			t.Fatalf("WriteText: %v", err)
		}
		out := buf.String()

		if !strings.Contains(out, "\033[") {
			t.Error("expected ANSI codes in color output")
		}
	})
}
