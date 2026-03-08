package section3

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/pscheid92/pgharden/internal/domain"
)

func newMockEnv(t *testing.T) (pgxmock.PgxConnIface, *domain.Environment) {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock, &domain.Environment{DB: mock, PGVersion: 16}
}

func TestCheck_3_2_PgAuditConfigured(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("pg_stat_statements,pgaudit"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("pgaudit.log").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("ddl,write"))

	c := &check_3_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_3_2_PgAuditNotLoaded(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("pg_stat_statements"))

	c := &check_3_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestCheck_3_2_PgAuditLogNone(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("pgaudit"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("pgaudit.log").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("none"))

	c := &check_3_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL when pgaudit.log=none, got %s", result.Status)
	}
}

func TestCheck_3_1_22_AllTokensPresent(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("log_line_prefix").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("%m [%p] %d %u %a %h "))

	c := &check_3_1_22{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_3_1_22_MissingTokens(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("log_line_prefix").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("%m [%p]"))

	c := &check_3_1_22{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for missing tokens, got %s", result.Status)
	}
}

func TestCheck_3_1_22_RDSTokens(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformRDS
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("log_line_prefix").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("%t:%r:%u@%d:[%p]:"))

	c := &check_3_1_22{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for RDS log_line_prefix, got %s", result.Status)
	}
}

func TestCheck_3_1_22_RDSTokensMissing(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformAurora
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("log_line_prefix").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("%t:%u"))

	c := &check_3_1_22{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for Aurora with missing tokens, got %s", result.Status)
	}
}

// --- 3.1.3: logging_collector ---

func TestCheck_3_1_3_BareMetal_On(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformBareMetal
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("logging_collector").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("on"))

	c := &check_3_1_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for logging_collector=on on bare-metal, got %s", result.Status)
	}
}

func TestCheck_3_1_3_BareMetal_Off(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformBareMetal
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("logging_collector").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))

	c := &check_3_1_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for logging_collector=off on bare-metal, got %s", result.Status)
	}
}

func TestCheck_3_1_3_Container_Off(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformContainer
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("logging_collector").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))

	c := &check_3_1_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for logging_collector=off on container, got %s", result.Status)
	}
}

// --- 3.2: pgaudit via extension fallback ---

func TestCheck_3_2_ExtensionFallback_Installed(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformRDS

	// First query: shared_preload_libraries returns no rows (permission denied)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}))

	// Fallback: check pg_extension
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

	// pgaudit.log setting
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("pgaudit.log").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("ddl"))

	c := &check_3_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for pgaudit via extension fallback, got %s", result.Status)
	}
}

func TestCheck_3_2_ExtensionFallback_NotInstalled(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformRDS

	// shared_preload_libraries returns no rows → ErrPermissionDenied
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}))

	// Fallback: check pg_extension → not found
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	c := &check_3_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL when pgaudit extension not installed, got %s", result.Status)
	}
}
