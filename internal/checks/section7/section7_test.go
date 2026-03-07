package section7

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

func TestCheck_7_1_DedicatedReplUser(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Superusers = []string{"postgres"}
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolreplication").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).
			AddRow("postgres").
			AddRow("replicator"))

	c := &check_7_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS with dedicated replication user, got %s", result.Status)
	}
}

func TestCheck_7_1_OnlySuperuserReplication(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Superusers = []string{"postgres"}
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolreplication").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).AddRow("postgres"))

	c := &check_7_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL when only superuser has REPLICATION, got %s", result.Status)
	}
}

func TestCheck_7_1_NoReplicationUsers(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolreplication").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}))

	c := &check_7_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL when no replication users exist, got %s", result.Status)
	}
}

func TestCheck_7_4_ArchiveEnabled(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings WHERE name").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("archive_mode", "on").
			AddRow("archive_command", "/bin/true"))

	c := &check_7_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_7_4_ArchiveDisabled(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings WHERE name").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("archive_mode", "off"))

	c := &check_7_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL, got %s", result.Status)
	}
}

func TestCheck_7_5_NotReplica(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("primary_conninfo").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	c := &check_7_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS when not a replica, got %s", result.Status)
	}
}

func TestCheck_7_5_ReplicaWithSSL(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("primary_conninfo").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).
			AddRow("host=primary sslmode=verify-full sslcompression=1"))

	c := &check_7_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS with sslmode=verify-full, got %s", result.Status)
	}
}

func TestCheck_7_5_ReplicaNoSSL(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("primary_conninfo").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).
			AddRow("host=primary port=5432"))

	c := &check_7_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL when sslmode not specified, got %s", result.Status)
	}
}

func TestCheck_7_5_ReplicaWeakSSL(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("primary_conninfo").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).
			AddRow("host=primary sslmode=prefer"))

	c := &check_7_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for sslmode=prefer, got %s", result.Status)
	}
}

// --- 7.1: RDS check ---

func TestCheck_7_1_RDSReplicationRoleExists(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformRDS
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

	c := &check_7_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for rds_replication role on RDS, got %s", result.Status)
	}
}

func TestCheck_7_1_RDSReplicationRoleMissing(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformRDS
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	c := &check_7_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL when rds_replication missing on RDS, got %s", result.Status)
	}
}
