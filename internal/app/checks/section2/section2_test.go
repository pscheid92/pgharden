//go:build !windows

package section2

import (
	"context"
	"io/fs"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/pgharden/pgharden/internal/domain"
)

func newMockEnv(t *testing.T) (pgxmock.PgxConnIface, *domain.Environment) {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock, &domain.Environment{DB: mock, PGVersion: 16, HasFilesystem: true}
}

// --- 2.2: extension directory permissions ---

func TestCheck_2_2_RootOwnedCorrectPerms(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("dynamic_library_path").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/usr/lib/postgresql/16/lib"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/usr/lib/postgresql/16/lib"))
	env.FS = fstest.MapFS{
		"usr/lib/postgresql/16/lib": {
			Mode: fs.ModeDir | 0755,
			Sys:  &syscall.Stat_t{Uid: 0},
		},
	}

	c := &check_2_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for root-owned 0755, got %s", result.Status)
	}
}

func TestCheck_2_2_NotRootOwned(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("dynamic_library_path").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/usr/lib/postgresql/16/lib"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/usr/lib/postgresql/16/lib"))
	env.FS = fstest.MapFS{
		"usr/lib/postgresql/16/lib": {
			Mode: fs.ModeDir | 0755,
			Sys:  &syscall.Stat_t{Uid: 1000},
		},
	}

	c := &check_2_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for non-root owner, got %s", result.Status)
	}
}

func TestCheck_2_2_WorldWritable(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("dynamic_library_path").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/usr/lib/postgresql/16/lib"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/usr/lib/postgresql/16/lib"))
	env.FS = fstest.MapFS{
		"usr/lib/postgresql/16/lib": {
			Mode: fs.ModeDir | 0777,
			Sys:  &syscall.Stat_t{Uid: 0},
		},
	}

	c := &check_2_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for world-writable mode, got %s", result.Status)
	}
}

// --- 2.3: .psql_history ---

func TestCheck_2_3_HistoryExists(t *testing.T) {
	_, env := newMockEnv(t)
	env.FS = fstest.MapFS{
		"home":                    {Mode: fs.ModeDir | 0755},
		"home/postgres":          {Mode: fs.ModeDir | 0700},
		"home/postgres/.psql_history": {Data: []byte("SELECT 1;\n")},
	}

	c := &check_2_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for .psql_history present, got %s", result.Status)
	}
}

func TestCheck_2_3_HistorySymlinkedToDevNull(t *testing.T) {
	_, env := newMockEnv(t)
	env.FS = fstest.MapFS{
		"home":                    {Mode: fs.ModeDir | 0755},
		"home/postgres":          {Mode: fs.ModeDir | 0700},
		"home/postgres/.psql_history": {Data: []byte("/dev/null"), Mode: fs.ModeSymlink},
	}

	c := &check_2_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for .psql_history -> /dev/null, got %s", result.Status)
	}
}

func TestCheck_2_3_NoHistory(t *testing.T) {
	_, env := newMockEnv(t)
	env.FS = fstest.MapFS{
		"home":           {Mode: fs.ModeDir | 0755},
		"home/postgres":  {Mode: fs.ModeDir | 0700},
	}

	c := &check_2_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS when no history file, got %s", result.Status)
	}
}

// --- 2.4: .pg_service.conf passwords ---

func TestCheck_2_4_PasswordInServiceConf(t *testing.T) {
	_, env := newMockEnv(t)
	env.FS = fstest.MapFS{
		"home":                             {Mode: fs.ModeDir | 0755},
		"home/postgres":                    {Mode: fs.ModeDir | 0700},
		"home/postgres/.pg_service.conf": {Data: []byte("[mydb]\nhost=localhost\npassword=secret\n")},
	}

	c := &check_2_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for password in .pg_service.conf, got %s", result.Status)
	}
}

func TestCheck_2_4_NoPasswordInServiceConf(t *testing.T) {
	_, env := newMockEnv(t)
	env.FS = fstest.MapFS{
		"home":                             {Mode: fs.ModeDir | 0755},
		"home/postgres":                    {Mode: fs.ModeDir | 0700},
		"home/postgres/.pg_service.conf": {Data: []byte("[mydb]\nhost=localhost\ndbname=mydb\n")},
	}

	c := &check_2_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS when no password in service conf, got %s", result.Status)
	}
}

// --- 2.5: pg_hba.conf permissions ---

func TestCheck_2_5_RestrictivePerms(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("hba_file").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/etc/postgresql/16/main/pg_hba.conf"))
	env.FS = fstest.MapFS{
		"etc/postgresql/16/main/pg_hba.conf": {Data: []byte("local all all peer\n"), Mode: 0600},
	}

	c := &check_2_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for 0600 permissions, got %s", result.Status)
	}
}

func TestCheck_2_5_OverlyPermissive(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("hba_file").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/etc/postgresql/16/main/pg_hba.conf"))
	env.FS = fstest.MapFS{
		"etc/postgresql/16/main/pg_hba.conf": {Data: []byte("local all all peer\n"), Mode: 0644},
	}

	c := &check_2_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for 0644 permissions, got %s", result.Status)
	}
}

// --- 2.6: unix socket directory permissions ---

func TestCheck_2_6_AcceptablePerms(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("unix_socket_directories").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/var/run/postgresql"))
	env.FS = fstest.MapFS{
		"var/run/postgresql": {Mode: fs.ModeDir | 0755},
	}

	c := &check_2_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for 0755 socket dir, got %s", result.Status)
	}
}

func TestCheck_2_6_WorldWritable(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("unix_socket_directories").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("/tmp"))
	env.FS = fstest.MapFS{
		"tmp": {Mode: fs.ModeDir | 0777},
	}

	c := &check_2_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for world-writable socket dir, got %s", result.Status)
	}
}

// --- 2.7: PGDATA permissions ---

func TestCheck_2_7_CorrectPermissions(t *testing.T) {
	_, env := newMockEnv(t)
	env.DataDir = "/var/lib/postgresql/16/main"
	env.FS = fstest.MapFS{
		"var/lib/postgresql/16/main": {Mode: fs.ModeDir | 0700},
	}

	c := &check_2_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for 0700 PGDATA, got %s", result.Status)
	}
}

func TestCheck_2_7_IncorrectPermissions(t *testing.T) {
	_, env := newMockEnv(t)
	env.DataDir = "/var/lib/postgresql/16/main"
	env.FS = fstest.MapFS{
		"var/lib/postgresql/16/main": {Mode: fs.ModeDir | 0755},
	}

	c := &check_2_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for 0755 PGDATA, got %s", result.Status)
	}
}

// --- 2.1: umask ---

type mockCmd struct {
	outputs map[string]string
	errors  map[string]error
}

func (m *mockCmd) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if err, ok := m.errors[key]; ok {
		return []byte(m.outputs[key]), err
	}
	return []byte(m.outputs[key]), nil
}

func TestCheck_2_1_CorrectUmask(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"sh": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{"sh -c umask": "0077"},
	}

	c := &check_2_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for umask 0077, got %s", result.Status)
	}
}

func TestCheck_2_1_IncorrectUmask(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"sh": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{"sh -c umask": "0022"},
	}

	c := &check_2_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for umask 0022, got %s", result.Status)
	}
}
