package section1

import (
	"context"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

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

// --- Filesystem tests ---

func TestCheck_1_3_FilesystemFallback(t *testing.T) {
	mock, env := newMockEnv(t)
	env.HasFilesystem = true
	env.DataDir = "/var/lib/postgresql/16/main"
	env.FS = fstest.MapFS{
		"var/lib/postgresql/16/main/PG_VERSION": {Data: []byte("16\n")},
	}
	mock.ExpectQuery("SELECT pg_read_file").
		WillReturnError(fmt.Errorf("permission denied"))

	c := &check_1_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS via filesystem fallback, got %s", result.Status)
	}
}

func TestCheck_1_6_PasswordFound(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/profile": {Data: []byte("export PGPASSWORD=secret\n")},
	}

	c := &check_1_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for PGPASSWORD in profile, got %s", result.Status)
	}
}

func TestCheck_1_6_NoPassword(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/profile": {Data: []byte("export PATH=/usr/bin\n")},
	}

	c := &check_1_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS when no PGPASSWORD, got %s", result.Status)
	}
}

func TestCheck_1_7_PasswordInProc(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.OS = "linux"
	env.FS = fstest.MapFS{
		"proc/123/environ": {Data: []byte("HOME=/root\x00PGPASSWORD=secret\x00")},
		"proc/456/environ": {Data: []byte("HOME=/home/user\x00")},
	}

	c := &check_1_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for PGPASSWORD in /proc, got %s", result.Status)
	}
}

func TestCheck_1_7_NoPasswordInProc(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.OS = "linux"
	env.FS = fstest.MapFS{
		"proc/123/environ": {Data: []byte("HOME=/root\x00PATH=/usr/bin\x00")},
	}

	c := &check_1_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_1_7_SkipsNonLinux(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.OS = "darwin"

	c := &check_1_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusSkipped {
		t.Errorf("expected SKIPPED on non-linux, got %s", result.Status)
	}
}

func TestCheck_1_4_4_WalSymlink(t *testing.T) {
	mock, env := newMockEnv(t)
	env.HasFilesystem = true
	env.DataDir = "/pgdata"
	env.FS = fstest.MapFS{
		"pgdata/pg_wal": {Data: []byte("/mnt/wal"), Mode: fs.ModeSymlink},
	}
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("temp_tablespaces").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("fast_ssd"))

	c := &check_1_4_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for symlinked pg_wal + temp_tablespaces, got %s", result.Status)
	}
}

func TestCheck_1_4_4_WalNotSymlink(t *testing.T) {
	mock, env := newMockEnv(t)
	env.HasFilesystem = true
	env.DataDir = "/pgdata"
	env.FS = fstest.MapFS{
		"pgdata/pg_wal": {Mode: fs.ModeDir | 0700},
	}
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("temp_tablespaces").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	c := &check_1_4_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for non-symlink pg_wal, got %s", result.Status)
	}
}

func TestCheck_1_1_1_PGDGFound(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/apt/sources.list.d/pgdg.list": {Data: []byte("deb http://apt.postgresql.org/pub/repos/apt ...")},
	}

	c := &check_1_1_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for PGDG repo found, got %s", result.Status)
	}
}

func TestCheck_1_1_1_PGDGInSourcesList(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/apt/sources.list": {Data: []byte("deb http://apt.postgresql.org/pub/repos/apt pgdg main\n")},
	}

	c := &check_1_1_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for pgdg in sources.list, got %s", result.Status)
	}
}
