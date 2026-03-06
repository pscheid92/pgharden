package checker

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestSettingCheckEq(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW ssl"] = "on"
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.1", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestSettingCheckEqFail(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW ssl"] = "off"
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.1", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestSettingCheckNeq(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW log_destination"] = "stderr"
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.2", Setting: "log_destination", Expected: "", Comparator: "neq", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS for non-empty value with neq, got %s", result.Status)
	}
}

func TestSettingCheckNeqFail(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW log_destination"] = ""
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.2", Setting: "log_destination", Expected: "", Comparator: "neq", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFail {
		t.Errorf("expected FAIL for empty value with neq, got %s", result.Status)
	}
}

func TestSettingCheckContains(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW shared_preload_libraries"] = "pg_stat_statements,pgaudit"
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.3", Setting: "shared_preload_libraries", Expected: "pgaudit", Comparator: "contains", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestSettingCheckOneof(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW log_statement"] = "ddl"
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.4", Setting: "log_statement", Expected: "ddl,all", Comparator: "oneof", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusPass {
		t.Errorf("expected PASS for 'ddl' in oneof 'ddl,all', got %s", result.Status)
	}
}

func TestSettingCheckOneofFail(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW log_statement"] = "none"
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.4", Setting: "log_statement", Expected: "ddl,all", Comparator: "oneof", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFail {
		t.Errorf("expected FAIL for 'none' not in oneof 'ddl,all', got %s", result.Status)
	}
}

func TestSettingCheckPermissionDenied(t *testing.T) {
	db := newMockDB()
	db.errors["SHOW ssl"] = fmt.Errorf("permission denied for parameter")
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.5", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusSkipped {
		t.Errorf("expected SKIPPED for permission denied, got %s", result.Status)
	}
}

func TestSettingCheckQueryError(t *testing.T) {
	db := newMockDB()
	db.errors["SHOW ssl"] = fmt.Errorf("connection lost")
	env := &Environment{DB: db}

	c := &SettingCheck{CheckID: "t.6", Setting: "ssl", Expected: "on", Sev: SeverityWarning}
	_, err := c.Run(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for connection lost")
	}
	if errors.Is(err, ErrPermissionDenied) {
		t.Error("should not be permission denied")
	}
}

func TestSettingCheckCustomMessages(t *testing.T) {
	db := newMockDB()
	db.scalars["SHOW ssl"] = "on"
	env := &Environment{DB: db}

	c := &SettingCheck{
		CheckID: "t.7", Setting: "ssl", Expected: "on", Sev: SeverityWarning,
		SuccessMsg: "SSL is good!",
		FailureMsg: "SSL is bad!",
	}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Messages[0].Content != "SSL is good!" {
		t.Errorf("expected custom success msg, got %q", result.Messages[0].Content)
	}
}
