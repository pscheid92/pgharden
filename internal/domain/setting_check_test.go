package domain

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
)

func TestSettingCheckEq(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow("on"),
	)

	c := &SettingCheck{CheckID: "t.1", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestSettingCheckEqFail(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow("off"),
	)

	c := &SettingCheck{CheckID: "t.1", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestSettingCheckNeq(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow("stderr"),
	)

	c := &SettingCheck{CheckID: "t.2", Setting: "log_destination", Expected: "", Comparator: "neq", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS for non-empty value with neq, got %s", result.Status)
	}
}

func TestSettingCheckNeqFail(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow(""),
	)

	c := &SettingCheck{CheckID: "t.2", Setting: "log_destination", Expected: "", Comparator: "neq", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFail {
		t.Errorf("expected FAIL for empty value with neq, got %s", result.Status)
	}
}

func TestSettingCheckContains(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow("pg_stat_statements,pgaudit"),
	)

	c := &SettingCheck{CheckID: "t.3", Setting: "shared_preload_libraries", Expected: "pgaudit", Comparator: "contains", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestSettingCheckOneof(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow("ddl"),
	)

	c := &SettingCheck{CheckID: "t.4", Setting: "log_statement", Expected: "ddl,all", Comparator: "oneof", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS for 'ddl' in oneof 'ddl,all', got %s", result.Status)
	}
}

func TestSettingCheckOneofFail(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
		pgxmock.NewRows([]string{"setting"}).AddRow("none"),
	)

	c := &SettingCheck{CheckID: "t.4", Setting: "log_statement", Expected: "ddl,all", Comparator: "oneof", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFail {
		t.Errorf("expected FAIL for 'none' not in oneof 'ddl,all', got %s", result.Status)
	}
}

func TestSettingCheckPermissionDenied(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnError(&pgconn.PgError{Code: "42501"})

	c := &SettingCheck{CheckID: "t.5", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), &Environment{DB: mock})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusSkipped {
		t.Errorf("expected SKIPPED for permission denied, got %s", result.Status)
	}
}

func TestSettingCheckQueryError(t *testing.T) {
	mock := newMockDB(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnError(fmt.Errorf("connection lost"))

	c := &SettingCheck{CheckID: "t.6", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	_, err := c.Run(context.Background(), &Environment{DB: mock})
	if err == nil {
		t.Fatal("expected error for connection lost")
	}
	if errors.Is(err, ErrPermissionDenied) {
		t.Error("should not be permission denied")
	}
}
