package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pgharden/pgharden/internal/config"
	"github.com/pgharden/pgharden/internal/report"
)

func startPostgres(t *testing.T, ctx context.Context) (host string, port int) {
	t.Helper()

	// testcontainers panics if Docker is not available — recover and skip.
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("skipping: Docker not available (%v)", r)
		}
	}()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Skipf("skipping: failed to start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	h, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}
	p, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get container port: %v", err)
	}

	return h, p.Int()
}

func TestIntegrationFullScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	host, port := startPostgres(t, ctx)

	cfg := config.DefaultConfig()
	cfg.Host = host
	cfg.Port = port
	cfg.User = "postgres"
	cfg.DSN = fmt.Sprintf("host=%s port=%d user=postgres password=testpass dbname=postgres sslmode=disable", host, port)
	cfg.Format = "json"
	cfg.Output = ""

	opts := &RunOptions{FormatExplicit: true}

	// Run the full scan, capturing JSON output.
	var buf bytes.Buffer
	exitCode, err := runToWriter(ctx, cfg, opts, &buf)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Parse the JSON report.
	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON report: %v\nraw output:\n%s", err, buf.String())
	}

	// Basic assertions.
	if rpt.Summary.Total == 0 {
		t.Fatal("report has 0 total checks — expected checks to run")
	}

	t.Logf("Checks: %d total, %d passed, %d failed, %d skipped, %d manual",
		rpt.Summary.Total, rpt.Summary.Passed, rpt.Summary.Failed,
		rpt.Summary.Skipped, rpt.Summary.Manual)

	// Every check should have a status — no nils or empty results.
	for _, cat := range rpt.Categories {
		for _, check := range cat.Checks {
			if check.Status == "" {
				t.Errorf("check %s has empty status", check.ID)
			}
			if check.Status == "ERROR" {
				t.Errorf("check %s returned ERROR: %v", check.ID, check.Messages)
			}
		}
	}

	// Exit code should be valid.
	if exitCode < 0 || exitCode > 3 {
		t.Errorf("unexpected exit code: %d", exitCode)
	}
}

func TestIntegrationSectionFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	host, port := startPostgres(t, ctx)

	cfg := config.DefaultConfig()
	cfg.DSN = fmt.Sprintf("host=%s port=%d user=postgres password=testpass dbname=postgres sslmode=disable", host, port)
	cfg.Format = "json"
	cfg.IncludeSection = "3"

	opts := &RunOptions{FormatExplicit: true}

	var buf bytes.Buffer
	_, err := runToWriter(ctx, cfg, opts, &buf)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}

	if len(rpt.Categories) != 1 {
		t.Fatalf("expected 1 category (section 3), got %d", len(rpt.Categories))
	}
	if rpt.Categories[0].ID != "3" {
		t.Errorf("expected section 3, got %s", rpt.Categories[0].ID)
	}

	t.Logf("Section 3: %d checks", rpt.Summary.Total)
}
