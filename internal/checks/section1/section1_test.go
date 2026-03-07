package section1

import (
	"context"
	"fmt"
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

func TestCheck_1_3_SQLPass(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnRows(pgxmock.NewRows([]string{"pg_read_file"}).AddRow("16\n"))

	c := &check_1_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_1_3_NoAccessSkips(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnError(fmt.Errorf("permission denied"))

	c := &check_1_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusSkipped {
		t.Errorf("expected SKIPPED, got %s", result.Status)
	}
}

func TestCheck_1_4_1_SQLPass(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnRows(pgxmock.NewRows([]string{"pg_read_file"}).AddRow("16\n"))

	c := &check_1_4_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_1_4_1_SQLMismatch(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnRows(pgxmock.NewRows([]string{"pg_read_file"}).AddRow("15\n"))

	c := &check_1_4_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestCheck_1_4_2_SQLPass(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnRows(pgxmock.NewRows([]string{"pg_read_file"}).AddRow("16\n"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("server_version_num").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("160004"))

	c := &check_1_4_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_1_4_2_SQLMismatch(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnRows(pgxmock.NewRows([]string{"pg_read_file"}).AddRow("15\n"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("server_version_num").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("160004"))

	c := &check_1_4_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestCheck_1_4_3_ChecksumsEnabled(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("data_checksums").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("on"))

	c := &check_1_4_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_1_4_3_ChecksumsDisabled(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("data_checksums").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))

	c := &check_1_4_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestCheck_1_8_Extensions(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT e.extname").
		WillReturnRows(pgxmock.NewRows([]string{"extname", "extversion", "nspname"}).
			AddRow("plpgsql", "1.0", "pg_catalog").
			AddRow("pgcrypto", "1.3", "public"))

	c := &check_1_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
	// Header + 2 extensions
	if len(result.Details) != 3 {
		t.Errorf("expected 3 detail rows (header + 2), got %d", len(result.Details))
	}
}

func TestCheck_1_8_NoExtensions(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT e.extname").
		WillReturnRows(pgxmock.NewRows([]string{"extname", "extversion", "nspname"}))

	c := &check_1_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
}

func TestCheck_1_9_NoTablespaces(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT spcname").
		WillReturnRows(pgxmock.NewRows([]string{"spcname", "location"}))

	c := &check_1_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
}

func TestCheck_1_9_CustomTablespaces(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT spcname").
		WillReturnRows(pgxmock.NewRows([]string{"spcname", "location"}).
			AddRow("fast_ssd", "/mnt/ssd/pg"))

	c := &check_1_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
	if len(result.Details) != 2 {
		t.Errorf("expected 2 detail rows (header + 1), got %d", len(result.Details))
	}
}
