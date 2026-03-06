package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteHTML(t *testing.T) {
	rpt := &Report{
		Metadata: Metadata{Host: "localhost", Port: 5432, ToolVersion: "test"},
		Summary:  Summary{Total: 2, Passed: 1, Failed: 1, BySeverity: map[string]int{"WARNING": 1}},
		Categories: []CategoryReport{
			{
				ID:    "1",
				Title: "Test Section",
				Checks: []CheckReport{
					{ID: "1.1", Title: "Pass Check", Status: "PASS", Severity: "INFO"},
					{ID: "1.2", Title: "Fail Check", Status: "FAIL", Severity: "WARNING",
						Messages: []MsgEntry{{Level: "FAILURE", Content: "Something wrong"}}},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, rpt); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "<html") {
		t.Error("output missing <html tag")
	}
	if !strings.Contains(out, "Pass Check") {
		t.Error("output missing check title")
	}
	if !strings.Contains(out, "Something wrong") {
		t.Error("output missing failure message")
	}
}
