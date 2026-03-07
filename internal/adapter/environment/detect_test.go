package environment

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
)

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"PostgreSQL 16.4 on x86_64-pc-linux-gnu", 16},
		{"PostgreSQL 15.2 (Ubuntu 15.2-1.pgdg22.04+1)", 15},
		{"PostgreSQL 14.10 on aarch64-unknown-linux-gnu", 14},
		{"PostgreSQL 9.6.24 on x86_64-pc-linux-gnu", 9},
		{"something else entirely", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMajorVersion(tt.input)
			if got != tt.want {
				t.Errorf("parseMajorVersion(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func newMock(t *testing.T) pgxmock.PgxConnIface {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock
}

// expectFullDetect sets up mock expectations for a complete Detect() call.
func expectFullDetect(mock pgxmock.PgxConnIface, superuser bool) {
	// SELECT version()
	mock.ExpectQuery("SELECT version").
		WillReturnRows(pgxmock.NewRows([]string{"version"}).
			AddRow("PostgreSQL 16.4 on aarch64-unknown-linux-musl"))

	// DetectPrivileges: rolsuper
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(superuser))
	// DetectPrivileges: rds_superuser
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	// DetectPrivileges: pg_monitor
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	// SHOW data_directory
	mock.ExpectQuery("SHOW data_directory").
		WillReturnRows(pgxmock.NewRows([]string{"data_directory"}).AddRow("/var/lib/postgresql/data"))

	// detectPlatform: check rds_superuser role
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	// detectPlatform: check archive_command
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("archive_command").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))
	// detectPlatform: check restore_command
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("restore_command").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	// pg_database
	mock.ExpectQuery("SELECT datname FROM pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname"}).
			AddRow("postgres").
			AddRow("template1"))

	// pg_roles superusers
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).AddRow("postgres"))
}

func TestDetect_PGVersion(t *testing.T) {
	mock := newMock(t)
	expectFullDetect(mock, true)

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if env.PGVersion != 16 {
		t.Errorf("expected PGVersion=16, got %d", env.PGVersion)
	}
	if env.PGVersionFull != "PostgreSQL 16.4 on aarch64-unknown-linux-musl" {
		t.Errorf("unexpected PGVersionFull: %s", env.PGVersionFull)
	}
}

func TestDetect_SuperuserPrivileges(t *testing.T) {
	mock := newMock(t)
	expectFullDetect(mock, true)

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if !env.IsSuperuser {
		t.Error("expected IsSuperuser=true")
	}
}

func TestDetect_NonSuperuserPrivileges(t *testing.T) {
	mock := newMock(t)
	expectFullDetect(mock, false)

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if env.IsSuperuser {
		t.Error("expected IsSuperuser=false")
	}
}

func TestDetect_Databases(t *testing.T) {
	mock := newMock(t)
	expectFullDetect(mock, true)

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Databases) != 2 {
		t.Errorf("expected 2 databases, got %d", len(env.Databases))
	}
}

func TestDetect_Superusers(t *testing.T) {
	mock := newMock(t)
	expectFullDetect(mock, true)

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Superusers) != 1 || env.Superusers[0] != "postgres" {
		t.Errorf("expected [postgres], got %v", env.Superusers)
	}
}

func TestDetect_VersionQueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("SELECT version").
		WillReturnError(context.DeadlineExceeded)

	_, err := Detect(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error when version query fails")
	}
}

func TestDetect_PlatformBareMetal(t *testing.T) {
	mock := newMock(t)
	expectFullDetect(mock, false)

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if env.Platform != "bare-metal" {
		t.Errorf("expected platform=bare-metal, got %s", env.Platform)
	}
}

func TestDetect_PlatformZalando(t *testing.T) {
	mock := newMock(t)

	mock.ExpectQuery("SELECT version").
		WillReturnRows(pgxmock.NewRows([]string{"version"}).
			AddRow("PostgreSQL 16.4 on x86_64-pc-linux-gnu"))
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(false))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SHOW data_directory").
		WillReturnRows(pgxmock.NewRows([]string{"data_directory"}).AddRow("/home/postgres/pgdata"))

	// detectPlatform: rds_superuser check
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	// detectPlatform: archive_command contains /controller/manager
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("archive_command").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).
			AddRow("/controller/manager wal-archive %p"))

	mock.ExpectQuery("SELECT datname FROM pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname"}).AddRow("postgres"))
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).AddRow("postgres"))

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if env.Platform != "zalando" {
		t.Errorf("expected platform=zalando, got %s", env.Platform)
	}
}

func TestDetect_PlatformRDS(t *testing.T) {
	mock := newMock(t)

	mock.ExpectQuery("SELECT version").
		WillReturnRows(pgxmock.NewRows([]string{"version"}).
			AddRow("PostgreSQL 16.4 on x86_64-pc-linux-gnu"))
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(false))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SHOW data_directory").
		WillReturnRows(pgxmock.NewRows([]string{"data_directory"}).AddRow("/rdsdbdata/db"))

	// detectPlatform: IsRDSSuperuser=true, so detectRDSOrAurora is called
	// aurora_version() fails -> RDS
	mock.ExpectQuery("SELECT aurora_version").
		WillReturnError(context.DeadlineExceeded)

	mock.ExpectQuery("SELECT datname FROM pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname"}).AddRow("postgres"))
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).AddRow("rdsadmin"))

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if env.Platform != "rds" {
		t.Errorf("expected platform=rds, got %s", env.Platform)
	}
}

func TestDetect_PlatformAurora(t *testing.T) {
	mock := newMock(t)

	mock.ExpectQuery("SELECT version").
		WillReturnRows(pgxmock.NewRows([]string{"version"}).
			AddRow("PostgreSQL 16.4 on x86_64-pc-linux-gnu"))
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(false))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SHOW data_directory").
		WillReturnRows(pgxmock.NewRows([]string{"data_directory"}).AddRow("/rdsdbdata/db"))

	// detectPlatform: IsRDSSuperuser=true, aurora_version() succeeds -> Aurora
	mock.ExpectQuery("SELECT aurora_version").
		WillReturnRows(pgxmock.NewRows([]string{"aurora_version"}).AddRow("3.4.0"))

	mock.ExpectQuery("SELECT datname FROM pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname"}).AddRow("postgres"))
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).AddRow("rdsadmin"))

	env, err := Detect(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if env.Platform != "aurora" {
		t.Errorf("expected platform=aurora, got %s", env.Platform)
	}
}
