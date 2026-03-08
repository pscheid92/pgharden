package section4

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

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

// --- 4.2: password expiration ---

func TestCheck_4_2_AllHaveExpiration(t *testing.T) {
	mock, env := newMockEnv(t)
	future := time.Now().Add(30 * 24 * time.Hour)
	mock.ExpectQuery("SELECT rolname, rolvaliduntil").
		WillReturnRows(pgxmock.NewRows([]string{"rolname", "rolvaliduntil"}).
			AddRow("appuser", &future).
			AddRow("reader", &future))

	c := &check_4_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS when all roles have valid expiration, got %s", result.Status)
	}
}

func TestCheck_4_2_NoExpiration(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname, rolvaliduntil").
		WillReturnRows(pgxmock.NewRows([]string{"rolname", "rolvaliduntil"}).
			AddRow("appuser", nil))

	c := &check_4_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for role with no expiration, got %s", result.Status)
	}
}

func TestCheck_4_2_ExpiredPassword(t *testing.T) {
	mock, env := newMockEnv(t)
	past := time.Now().Add(-30 * 24 * time.Hour)
	mock.ExpectQuery("SELECT rolname, rolvaliduntil").
		WillReturnRows(pgxmock.NewRows([]string{"rolname", "rolvaliduntil"}).
			AddRow("olduser", &past))

	c := &check_4_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for expired password, got %s", result.Status)
	}
}

func TestCheck_4_2_MixedExpiration(t *testing.T) {
	mock, env := newMockEnv(t)
	future := time.Now().Add(30 * 24 * time.Hour)
	past := time.Now().Add(-30 * 24 * time.Hour)
	mock.ExpectQuery("SELECT rolname, rolvaliduntil").
		WillReturnRows(pgxmock.NewRows([]string{"rolname", "rolvaliduntil"}).
			AddRow("gooduser", &future).
			AddRow("expireduser", &past).
			AddRow("noexpiry", nil))

	c := &check_4_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for mixed expiration states, got %s", result.Status)
	}
	// Should have header + 3 roles
	if len(result.Details) != 4 {
		t.Errorf("expected 4 detail rows (header + 3), got %d", len(result.Details))
	}
}

func TestCheck_4_3_SingleSuperuser(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).AddRow("postgres"))

	c := &check_4_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for single superuser, got %s", result.Status)
	}
}

func TestCheck_4_3_MultipleSuperusers(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).
			AddRow("postgres").
			AddRow("admin"))

	c := &check_4_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for multiple superusers, got %s", result.Status)
	}
	if len(result.Details) != 3 {
		t.Errorf("expected 3 detail rows (header + 2), got %d", len(result.Details))
	}
}

func TestCheck_4_3_RDSAdminExcluded(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformRDS
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).
			AddRow("postgres").
			AddRow("rdsadmin"))

	c := &check_4_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS when rdsadmin is filtered on RDS, got %s", result.Status)
	}
}

func TestCheck_4_3_RDSAdminNotExcludedOnBareMetal(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformBareMetal
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolsuper").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).
			AddRow("postgres").
			AddRow("rdsadmin"))

	c := &check_4_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL when rdsadmin is not filtered on bare-metal, got %s", result.Status)
	}
}

func TestCheck_4_4_LoginRoles(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname, rolconnlimit FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolname", "rolconnlimit"}).
			AddRow("appuser", 10).
			AddRow("reader", -1))

	c := &check_4_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
	// Header + 2 roles
	if len(result.Details) != 3 {
		t.Errorf("expected 3 detail rows, got %d", len(result.Details))
	}
	// reader has -1 → "unlimited"
	if result.Details[2][1] != "unlimited" {
		t.Errorf("expected 'unlimited' for connlimit -1, got %s", result.Details[2][1])
	}
}

func TestCheck_4_5_NoSecurityDefiner(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT n.nspname, p.proname").
		WillReturnRows(pgxmock.NewRows([]string{"nspname", "proname", "rolname", "prosecdef", "proconfig"}))

	c := &check_4_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS when no SECURITY DEFINER functions, got %s", result.Status)
	}
}

func TestCheck_4_5_HasSecurityDefiner(t *testing.T) {
	mock, env := newMockEnv(t)
	config := "{search_path=pg_catalog}"
	mock.ExpectQuery("SELECT n.nspname, p.proname").
		WillReturnRows(pgxmock.NewRows([]string{"nspname", "proname", "rolname", "prosecdef", "proconfig"}).
			AddRow("public", "admin_func", "postgres", true, &config))

	c := &check_4_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for SECURITY DEFINER function, got %s", result.Status)
	}
}

func TestCheck_4_6_NoExcessivePrivileges(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT grantee, table_schema").
		WillReturnRows(pgxmock.NewRows([]string{"grantee", "table_schema", "table_name", "privilege_type"}))

	c := &check_4_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_4_6_HasPrivileges(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT grantee, table_schema").
		WillReturnRows(pgxmock.NewRows([]string{"grantee", "table_schema", "table_name", "privilege_type"}).
			AddRow("appuser", "public", "users", "INSERT"))

	c := &check_4_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusManual {
		t.Errorf("expected MANUAL for review, got %s", result.Status)
	}
}

func TestCheck_4_7_NoRLS(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT n.nspname, c.relname").
		WillReturnRows(pgxmock.NewRows([]string{"nspname", "relname", "relrowsecurity", "relforcerowsecurity"}))

	c := &check_4_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
}

func TestCheck_4_7_HasRLS(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT n.nspname, c.relname").
		WillReturnRows(pgxmock.NewRows([]string{"nspname", "relname", "relrowsecurity", "relforcerowsecurity"}).
			AddRow("public", "users", true, true))

	c := &check_4_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
	if len(result.Details) != 2 {
		t.Errorf("expected 2 detail rows (header + 1), got %d", len(result.Details))
	}
}

func TestCheck_4_10_PublicSchemaNoCreate(t *testing.T) {
	mock, env := newMockEnv(t)
	acl := "{=U/postgres,postgres=UC/postgres}"
	mock.ExpectQuery("SELECT nspacl").
		WillReturnRows(pgxmock.NewRows([]string{"nspacl"}).AddRow(&acl))

	c := &check_4_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS when PUBLIC has no CREATE, got %s", result.Status)
	}
}

func TestCheck_4_10_PublicSchemaHasCreate(t *testing.T) {
	mock, env := newMockEnv(t)
	acl := "{=UC/postgres,postgres=UC/postgres}"
	mock.ExpectQuery("SELECT nspacl").
		WillReturnRows(pgxmock.NewRows([]string{"nspacl"}).AddRow(&acl))

	c := &check_4_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL when PUBLIC has CREATE, got %s", result.Status)
	}
}

func TestCheck_4_10_UsageOnlyNoCreate(t *testing.T) {
	mock, env := newMockEnv(t)
	// PUBLIC has only U (USAGE), no C (CREATE)
	acl := "{=U/postgres}"
	mock.ExpectQuery("SELECT nspacl").
		WillReturnRows(pgxmock.NewRows([]string{"nspacl"}).AddRow(&acl))

	c := &check_4_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for =U/postgres (USAGE only), got %s", result.Status)
	}
}

func TestCheck_4_10_MultipleACLEntries(t *testing.T) {
	mock, env := newMockEnv(t)
	// PUBLIC has U only, but a specific role has UC
	acl := "{=U/postgres,appuser=UC/postgres}"
	mock.ExpectQuery("SELECT nspacl").
		WillReturnRows(pgxmock.NewRows([]string{"nspacl"}).AddRow(&acl))

	c := &check_4_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// appuser has CREATE but they're named, not PUBLIC — should pass
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS (only named role has CREATE), got %s", result.Status)
	}
}

func TestCheck_4_10_PublicSchemaNullACL(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT nspacl").
		WillReturnRows(pgxmock.NewRows([]string{"nspacl"}).AddRow(nil))

	c := &check_4_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for NULL ACL (default privileges), got %s", result.Status)
	}
}

// --- 4.1: postgres user shell ---

func TestCheck_4_1_NoLoginShell(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0:root:/root:/bin/bash\npostgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/sbin/nologin\n")},
	}

	c := &check_4_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for nologin shell, got %s", result.Status)
	}
}

func TestCheck_4_1_InteractiveShell(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0:root:/root:/bin/bash\npostgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n")},
	}

	c := &check_4_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for /bin/bash shell, got %s", result.Status)
	}
}

func TestCheck_4_1_NoPostgresUser(t *testing.T) {
	_, env := newMockEnv(t)
	env.HasFilesystem = true
	env.FS = fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0:root:/root:/bin/bash\n")},
	}

	c := &check_4_1{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusSkipped {
		t.Errorf("expected SKIPPED when postgres user not found, got %s", result.Status)
	}
}
