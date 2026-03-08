package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/pscheid92/pgharden/internal/app/report"
	"github.com/pscheid92/pgharden/internal/app/scanner"
	"github.com/pscheid92/pgharden/internal/domain"
	"github.com/pscheid92/pgharden/internal/platform/config"
)

// mockConnector satisfies Connector for unit tests.
type mockConnector struct {
	err error
}

func (m *mockConnector) Connect(_ context.Context, _ *config.Config) (domain.DBQuerier, func(), error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return nil, func() {}, nil
}

// mockDetector satisfies Detector for unit tests by returning a pre-built Environment.
type mockDetector struct {
	env *domain.Environment
	err error
}

func (m *mockDetector) Detect(_ context.Context, _ domain.DBQuerier) (*domain.Environment, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.env, nil
}

func testEnv() *domain.Environment {
	return &domain.Environment{
		PGVersion:     16,
		PGVersionFull: "PostgreSQL 16.4 on x86_64",
		Platform:      domain.PlatformBareMetal,
		Commands:      map[string]bool{},
		Databases:     []string{"postgres"},
		Superusers:    []string{"postgres"},
	}
}

// bufferWriter is a test ReportWriter that writes to a bytes.Buffer.
type bufferWriter struct {
	buf    *bytes.Buffer
	format string
}

func (w *bufferWriter) WriteReport(rpt *report.Report) error {
	return writeReportTo(w.buf, w.format, rpt, false)
}

func newBufferWriter(buf *bytes.Buffer, format string) *bufferWriter {
	return &bufferWriter{buf: buf, format: format}
}

func TestRun_ConnectError(t *testing.T) {
	connector := &mockConnector{err: fmt.Errorf("connection refused")}
	detector := &mockDetector{env: testEnv()}
	cfg := config.DefaultConfig()

	var buf bytes.Buffer
	_, err := run(context.Background(), connector, detector, cfg, newBufferWriter(&buf, "json"))
	if err == nil {
		t.Fatal("expected error from failed connector")
	}
	if err.Error() != "connection refused" {
		t.Errorf("expected 'connection refused', got: %v", err)
	}
}

func TestRun_DetectEnvError(t *testing.T) {
	connector := &mockConnector{}
	detector := &mockDetector{err: fmt.Errorf("cannot parse version")}
	cfg := config.DefaultConfig()

	var buf bytes.Buffer
	_, err := run(context.Background(), connector, detector, cfg, newBufferWriter(&buf, "json"))
	if err == nil {
		t.Fatal("expected error from failed environment detection")
	}
	if !strings.Contains(err.Error(), "environment detection failed") {
		t.Errorf("expected 'environment detection failed', got: %v", err)
	}
}

func TestRun_JSONOutput(t *testing.T) {
	connector := &mockConnector{}
	detector := &mockDetector{env: testEnv()}
	cfg := config.DefaultConfig()
	cfg.IncludeChecks = []string{"0.0.0"} // nonexistent — skip all checks for fast test // skip all checks for fast test

	var buf bytes.Buffer
	exitCode, err := run(context.Background(), connector, detector, cfg, newBufferWriter(&buf, "json"))
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != scanner.ExitOK {
		t.Errorf("expected ExitOK, got %d", exitCode)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rpt.Metadata.PGVersionMajor != 16 {
		t.Errorf("expected PG version 16, got %d", rpt.Metadata.PGVersionMajor)
	}
}

func TestRun_TextOutput(t *testing.T) {
	connector := &mockConnector{}
	detector := &mockDetector{env: testEnv()}
	cfg := config.DefaultConfig()
	cfg.IncludeChecks = []string{"0.0.0"} // nonexistent — skip all checks for fast test

	var buf bytes.Buffer
	_, err := run(context.Background(), connector, detector, cfg, newBufferWriter(&buf, "text"))
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Error("expected text output, got empty buffer")
	}
}

func TestRun_HTMLOutput(t *testing.T) {
	connector := &mockConnector{}
	detector := &mockDetector{env: testEnv()}
	cfg := config.DefaultConfig()
	cfg.IncludeChecks = []string{"0.0.0"} // nonexistent — skip all checks for fast test

	var buf bytes.Buffer
	_, err := run(context.Background(), connector, detector, cfg, newBufferWriter(&buf, "html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<html") {
		t.Error("expected HTML output")
	}
}

func TestDetectEnv_PlatformOverride(t *testing.T) {
	detector := &mockDetector{env: testEnv()}
	cfg := config.DefaultConfig()
	cfg.Platform = "rds"

	env, err := detectEnv(context.Background(), detector, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if env.Platform != "rds" {
		t.Errorf("expected platform 'rds', got %q", env.Platform)
	}
}

func TestDetectEnv_LocalFlag(t *testing.T) {
	e := testEnv()
	e.DataDir = "/var/lib/postgresql/16/main"
	detector := &mockDetector{env: e}
	cfg := config.DefaultConfig()
	cfg.Local = true

	env, err := detectEnv(context.Background(), detector, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// EnableLocal populates Commands map by scanning PATH for known tools.
	// HasFilesystem depends on DataDir existing on the local filesystem,
	// which won't be true in tests. Just verify Commands was populated
	// (EnableLocal ran) — at least "sh" should be available.
	if !env.Commands["sh"] {
		t.Error("expected EnableLocal to discover 'sh' command")
	}
}

func TestDetectEnv_AllowExcludeDatabases(t *testing.T) {
	detector := &mockDetector{env: testEnv()}
	cfg := config.DefaultConfig()
	cfg.AllowDatabases = []string{"app_db"}
	cfg.ExcludeDatabases = []string{"template0"}

	env, err := detectEnv(context.Background(), detector, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.AllowDatabases) != 1 || env.AllowDatabases[0] != "app_db" {
		t.Errorf("expected AllowDatabases=[app_db], got %v", env.AllowDatabases)
	}
	if len(env.ExcludeDatabases) != 1 || env.ExcludeDatabases[0] != "template0" {
		t.Errorf("expected ExcludeDatabases=[template0], got %v", env.ExcludeDatabases)
	}
}

func TestScanOpts_MapsConfigFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.IncludeChecks = []string{"1.1", "1.2"}
	cfg.ExcludeChecks = []string{"2.1"}
	cfg.IncludeSection = "3"
	cfg.IncludeSource = "cis"
	cfg.Host = "db.example.com"
	cfg.Port = 5433
	cfg.Database = "mydb"

	opts := scanOpts(cfg)

	if len(opts.IncludeChecks) != 2 || opts.IncludeChecks[0] != "1.1" {
		t.Errorf("IncludeChecks not mapped: %v", opts.IncludeChecks)
	}
	if len(opts.ExcludeChecks) != 1 || opts.ExcludeChecks[0] != "2.1" {
		t.Errorf("ExcludeChecks not mapped: %v", opts.ExcludeChecks)
	}
	if opts.IncludeSection != "3" {
		t.Errorf("IncludeSection not mapped: %q", opts.IncludeSection)
	}
	if opts.IncludeSource != "cis" {
		t.Errorf("IncludeSource not mapped: %q", opts.IncludeSource)
	}
	if opts.Meta.Host != "db.example.com" {
		t.Errorf("Meta.Host not mapped: %q", opts.Meta.Host)
	}
	if opts.Meta.Port != 5433 {
		t.Errorf("Meta.Port not mapped: %d", opts.Meta.Port)
	}
	if opts.Meta.Database != "mydb" {
		t.Errorf("Meta.Database not mapped: %q", opts.Meta.Database)
	}
}
