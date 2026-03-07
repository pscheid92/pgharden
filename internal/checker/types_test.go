package checker

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
)

func TestShowSetting(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock := newMockDB(t)
		mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnRows(
			pgxmock.NewRows([]string{"setting"}).AddRow("on"),
		)
		val, err := ShowSetting(ctx, mock, "ssl")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "on" {
			t.Errorf("got %q, want %q", val, "on")
		}
	})

	t.Run("permission_denied", func(t *testing.T) {
		mock := newMockDB(t)
		mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnError(&pgconn.PgError{Code: "42501"})
		_, err := ShowSetting(ctx, mock, "ssl")
		if !errors.Is(err, ErrPermissionDenied) {
			t.Errorf("got %v, want ErrPermissionDenied", err)
		}
	})

	t.Run("other_error", func(t *testing.T) {
		mock := newMockDB(t)
		mock.ExpectQuery("SELECT setting FROM pg_settings").WithArgs(pgxmock.AnyArg()).WillReturnError(fmt.Errorf("connection lost"))
		_, err := ShowSetting(ctx, mock, "ssl")
		if err == nil || errors.Is(err, ErrPermissionDenied) {
			t.Errorf("expected non-permission error, got %v", err)
		}
	})
}

func TestShouldCheckDB(t *testing.T) {
	t.Run("allow_list", func(t *testing.T) {
		env := &Environment{AllowDatabases: []string{"mydb", "testdb"}}
		if !env.ShouldCheckDB("mydb") {
			t.Error("expected mydb to be allowed")
		}
		if env.ShouldCheckDB("other") {
			t.Error("expected other to be excluded")
		}
	})

	t.Run("exclude_list", func(t *testing.T) {
		env := &Environment{ExcludeDatabases: []string{"template0"}}
		if env.ShouldCheckDB("template0") {
			t.Error("expected template0 to be excluded")
		}
		if !env.ShouldCheckDB("mydb") {
			t.Error("expected mydb to be included")
		}
	})

	t.Run("no_filters", func(t *testing.T) {
		env := &Environment{}
		if !env.ShouldCheckDB("anything") {
			t.Error("expected all dbs to be included when no filters set")
		}
	})
}

func TestSeverityString(t *testing.T) {
	tests := map[Severity]string{
		SeverityInfo:     "INFO",
		SeverityWarning:  "WARNING",
		SeverityCritical: "CRITICAL",
		Severity(99):     "UNKNOWN",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestStatusString(t *testing.T) {
	tests := map[Status]string{
		StatusPass:    "PASS",
		StatusFail:    "FAIL",
		StatusSkipped: "SKIPPED",
		StatusManual:  "MANUAL",
		Status(99):    "UNKNOWN",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", s, got, want)
		}
	}
}
