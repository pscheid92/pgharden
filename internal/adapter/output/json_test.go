package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pscheid92/pgharden/internal/app/report"
)

func TestWriteJSON(t *testing.T) {
	rpt := &report.Report{
		Metadata: report.Metadata{Host: "localhost", Port: 5432},
		Summary:  report.Summary{Total: 1, Passed: 1, BySeverity: map[string]int{}},
		Categories: []report.CategoryReport{
			{
				ID:    "1",
				Title: "Section 1",
				Checks: []report.CheckReport{
					{ID: "1.1", Status: "PASS", Severity: "INFO"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, rpt); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Verify valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, buf.String())
	}

	if _, ok := parsed["metadata"]; !ok {
		t.Error("JSON missing 'metadata' key")
	}
	if _, ok := parsed["summary"]; !ok {
		t.Error("JSON missing 'summary' key")
	}
	if _, ok := parsed["categories"]; !ok {
		t.Error("JSON missing 'categories' key")
	}
}
