package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

// TestIntegrationCheckCorrectness verifies that specific checks produce expected
// results against a default PG 16 Alpine container.
func TestIntegrationCheckCorrectness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	host, port := startPostgres(t, ctx)

	cfg := config.DefaultConfig()
	cfg.DSN = fmt.Sprintf("host=%s port=%d user=postgres password=testpass dbname=postgres sslmode=disable", host, port)
	cfg.Format = "json"

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

	// PG 16 Alpine defaults — these are stable, known values.
	expectations := []struct {
		checkID  string
		status   string
		severity string // optional, empty means don't check
	}{
		// listen_addresses='*' in container
		{"5.2", "FAIL", "CRITICAL"},
		// ssl=off (no certs in container)
		{"6.8", "FAIL", "CRITICAL"},
		// password_encryption=scram-sha-256 (PG 16 default)
		{"5.12", "PASS", ""},
		// data_checksums=off (default initdb)
		{"1.4.3", "FAIL", ""},
		// Only postgres superuser exists
		{"4.3", "PASS", ""},
		// PG 15+ revoked CREATE from PUBLIC on the public schema
		{"4.10", "PASS", ""},
		// archive_mode=off (default)
		{"7.4", "FAIL", ""},
		// No pgaudit in shared_preload_libraries
		{"3.2", "FAIL", ""},
		// log_connections=off (default)
		{"3.1.20", "FAIL", ""},
		// log_statement=none (default, expects ddl or all)
		{"3.1.23", "FAIL", ""},
		// No credcheck/passwordcheck loaded
		{"5.6", "FAIL", ""},
		// log_replication_commands=off (default)
		{"7.2", "FAIL", ""},
	}

	for _, exp := range expectations {
		t.Run(exp.checkID, func(t *testing.T) {
			check := findCheck(&rpt, exp.checkID)
			if check == nil {
				t.Fatalf("check %s not found in report", exp.checkID)
			}
			if check.Status == "SKIPPED" {
				t.Skipf("check %s was skipped: %s", exp.checkID, check.SkipReason)
			}
			if check.Status != exp.status {
				t.Errorf("check %s: expected %s, got %s (messages: %v)",
					exp.checkID, exp.status, check.Status, check.Messages)
			}
			if exp.severity != "" && check.Severity != exp.severity {
				t.Errorf("check %s: expected severity %s, got %s",
					exp.checkID, exp.severity, check.Severity)
			}
		})
	}
}

// TestIntegrationAlteredConfig verifies checks after altering PostgreSQL settings.
func TestIntegrationAlteredConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	host, port := startPostgres(t, ctx)

	dsn := fmt.Sprintf("host=%s port=%d user=postgres password=testpass dbname=postgres sslmode=disable", host, port)

	// Connect and alter settings.
	setupConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("setup connect: %v", err)
	}

	// Create a second superuser → 4.3 should FAIL
	_, err = setupConn.Exec(ctx, "CREATE ROLE testadmin SUPERUSER LOGIN PASSWORD 'testpass'")
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Set password_encryption to md5 → 5.12 should FAIL
	_, err = setupConn.Exec(ctx, "ALTER SYSTEM SET password_encryption = 'md5'")
	if err != nil {
		t.Fatalf("alter system: %v", err)
	}

	_, err = setupConn.Exec(ctx, "SELECT pg_reload_conf()")
	if err != nil {
		t.Fatalf("reload conf: %v", err)
	}
	_ = setupConn.Close(ctx)

	// Run the scan.
	cfg := config.DefaultConfig()
	cfg.DSN = dsn
	cfg.Format = "json"
	opts := &RunOptions{FormatExplicit: true}

	var buf bytes.Buffer
	_, err = runToWriter(ctx, cfg, opts, &buf)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}

	t.Run("4.3_multiple_superusers", func(t *testing.T) {
		check := findCheck(&rpt, "4.3")
		if check == nil {
			t.Fatal("check 4.3 not found")
		}
		if check.Status != "FAIL" {
			t.Errorf("expected FAIL for multiple superusers, got %s", check.Status)
		}
	})

	t.Run("5.12_md5_encryption", func(t *testing.T) {
		check := findCheck(&rpt, "5.12")
		if check == nil {
			t.Fatal("check 5.12 not found")
		}
		if check.Status != "FAIL" {
			t.Errorf("expected FAIL for md5 encryption, got %s", check.Status)
		}
	})
}

func findCheck(rpt *report.Report, checkID string) *report.CheckReport {
	for _, cat := range rpt.Categories {
		for i := range cat.Checks {
			if cat.Checks[i].ID == checkID {
				return &cat.Checks[i]
			}
		}
	}
	return nil
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
