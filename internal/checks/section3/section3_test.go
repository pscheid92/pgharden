package section3

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/pgharden/pgharden/internal/checker"
)

func newMockEnv(t *testing.T) (pgxmock.PgxConnIface, *checker.Environment) {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock, &checker.Environment{DB: mock, PGVersion: 16}
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
	if result.Status != checker.StatusPass {
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
	if result.Status != checker.StatusFail {
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
	if result.Status != checker.StatusFail {
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
	if result.Status != checker.StatusPass {
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
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for missing tokens, got %s", result.Status)
	}
}
