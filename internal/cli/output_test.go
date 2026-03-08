package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pscheid92/pgharden/internal/app/report"
	"github.com/pscheid92/pgharden/internal/platform/config"
)

func sampleReport() *report.Report {
	return &report.Report{
		Summary: report.Summary{
			Total:      2,
			Passed:     1,
			Failed:     1,
			BySeverity: map[string]int{"WARNING": 1},
		},
		Categories: []report.CategoryReport{
			{
				ID:    "1",
				Title: "Installation",
				Checks: []report.CheckReport{
					{ID: "1.1", Title: "Check A", Status: "PASS", Severity: "INFO"},
					{ID: "1.2", Title: "Check B", Status: "FAIL", Severity: "WARNING",
						Messages: []report.MsgEntry{{Level: "FAILURE", Content: "something failed"}}},
				},
			},
		},
	}
}

func TestWriteReportTo_JSON(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	if err := writeReportTo(&buf, "json", rpt, false); err != nil {
		t.Fatal(err)
	}

	var parsed report.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Summary.Total != 2 {
		t.Errorf("expected 2 total, got %d", parsed.Summary.Total)
	}
}

func TestWriteReportTo_Text(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	if err := writeReportTo(&buf, "text", rpt, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "FAIL") {
		t.Errorf("text output should contain PASS and FAIL, got:\n%s", out)
	}
}

func TestWriteReportTo_HTML(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	if err := writeReportTo(&buf, "html", rpt, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<html") {
		t.Error("HTML output should contain <html tag")
	}
}

func TestWriteReportTo_UnsupportedFormat(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	err := writeReportTo(&buf, "xml", rpt, false)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected 'unsupported format' error, got: %v", err)
	}
}

func TestResolveFormat_ExplicitFormat(t *testing.T) {
	cfg := &config.Config{Format: "html"}
	opts := &RunOptions{FormatExplicit: true}
	resolveFormat(cfg, opts)
	if cfg.Format != "html" {
		t.Errorf("explicit format should be preserved, got %s", cfg.Format)
	}
}

func TestResolveFormat_OutputFileDefaultsToJSON(t *testing.T) {
	cfg := &config.Config{Format: "text", Output: "report.json"}
	opts := &RunOptions{}
	resolveFormat(cfg, opts)
	if cfg.Format != "json" {
		t.Errorf("output file should default to json, got %s", cfg.Format)
	}
}

func TestResolveFormat_TerminalDefaultsToText(t *testing.T) {
	orig := isTerminal
	isTerminal = func(*os.File) bool { return true }
	t.Cleanup(func() { isTerminal = orig })

	cfg := &config.Config{Format: "json"}
	opts := &RunOptions{}
	resolveFormat(cfg, opts)
	if cfg.Format != "text" {
		t.Errorf("terminal should default to text, got %s", cfg.Format)
	}
}

func TestResolveFormat_NonTerminalKeepsFormat(t *testing.T) {
	orig := isTerminal
	isTerminal = func(*os.File) bool { return false }
	t.Cleanup(func() { isTerminal = orig })

	cfg := &config.Config{Format: "json"}
	opts := &RunOptions{}
	resolveFormat(cfg, opts)
	if cfg.Format != "json" {
		t.Errorf("non-terminal should keep format, got %s", cfg.Format)
	}
}

func TestOpenOutput_Stdout(t *testing.T) {
	f, closer, err := openOutput("")
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if f != os.Stdout {
		t.Error("expected os.Stdout for empty path")
	}
}

func TestOpenOutput_File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-output.json")
	f, closer, err := openOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	if _, err := f.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	closer()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", data)
	}
}

func TestOpenOutput_InvalidPath(t *testing.T) {
	_, _, err := openOutput("/nonexistent/dir/file.json")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}
