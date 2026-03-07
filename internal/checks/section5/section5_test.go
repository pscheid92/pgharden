package section5

import (
	"context"
	"strings"
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
	return mock, &checker.Environment{DB: mock, PGVersion: 16, HBALoaded: true}
}

// --- 5.2: listen_addresses ---

func TestCheck_5_2_ListenSpecific(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("listen_addresses").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("localhost"))

	c := &check_5_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for localhost, got %s", result.Status)
	}
}

func TestCheck_5_2_ListenAll(t *testing.T) {
	for _, addr := range []string{"*", "0.0.0.0"} {
		t.Run(addr, func(t *testing.T) {
			mock, env := newMockEnv(t)
			mock.ExpectQuery("SELECT setting FROM pg_settings").
				WithArgs("listen_addresses").
				WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(addr))

			c := &check_5_2{}
			result, err := c.Run(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != checker.StatusFail {
				t.Errorf("expected FAIL for %q, got %s", addr, result.Status)
			}
		})
	}
}

// --- 5.3: local auth methods ---

func TestCheck_5_3_SecureLocalAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "local", Database: "all", User: "all", Method: "peer"},
		{LineNumber: 2, Type: "local", Database: "all", User: "postgres", Method: "scram-sha-256"},
	}

	c := &check_5_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for secure local auth, got %s", result.Status)
	}
}

func TestCheck_5_3_InsecureLocalAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "local", Database: "all", User: "all", Method: "trust"},
	}

	c := &check_5_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for trust auth, got %s", result.Status)
	}
	if result.Severity != checker.SeverityCritical {
		t.Errorf("expected CRITICAL severity for trust, got %s", result.Severity)
	}
}

func TestCheck_5_3_WeakLocalAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "local", Database: "all", User: "all", Method: "md5"},
	}

	c := &check_5_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for md5, got %s", result.Status)
	}
	if result.Severity != checker.SeverityWarning {
		t.Errorf("expected WARNING severity for md5, got %s", result.Severity)
	}
}

// --- 5.4: host auth methods ---

func TestCheck_5_4_SecureHostAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "all", User: "all", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_5_4_InsecureHostAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "password"},
	}

	c := &check_5_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for password auth, got %s", result.Status)
	}
	if result.Severity != checker.SeverityCritical {
		t.Errorf("expected CRITICAL for password, got %s", result.Severity)
	}
}

// --- 5.5: connection limits ---

func TestCheck_5_5_AllLimited(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolconnlimit").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}))

	c := &check_5_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_5_5_UnlimitedRoles(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolconnlimit").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}).
			AddRow("appuser").
			AddRow("reader"))

	c := &check_5_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for unlimited roles, got %s", result.Status)
	}
}

// --- 5.6: password complexity ---

func TestCheck_5_6_CredcheckLoaded(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("credcheck,pg_stat_statements"))

	c := &check_5_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS with credcheck, got %s", result.Status)
	}
}

func TestCheck_5_6_NoPasswordModule(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("pg_stat_statements"))

	c := &check_5_6{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL without password module, got %s", result.Status)
	}
}

// --- 5.7: auth timeout ---

func TestCheck_5_7_GoodTimeout(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("authentication_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("30"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("auth_delay"))

	c := &check_5_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// Both conditions met: timeout ≤60 and auth_delay loaded
	if result.Status == checker.StatusFail {
		t.Errorf("expected non-FAIL with good timeout and auth_delay, got FAIL")
	}
}

func TestCheck_5_7_HighTimeout(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("authentication_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("120"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("shared_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("auth_delay"))

	c := &check_5_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for 120s timeout, got %s", result.Status)
	}
}

// --- 5.8: SSL for host connections ---

func TestCheck_5_8_AllSSL(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "all", User: "all", Address: "10.0.0.0/8", Method: "scram-sha-256"},
		{LineNumber: 2, Type: "host", Database: "all", User: "all", Address: "127.0.0.1/32", Method: "scram-sha-256"},
	}

	c := &check_5_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS (hostssl + localhost), got %s", result.Status)
	}
}

func TestCheck_5_8_PlainHost(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for plain host on non-local, got %s", result.Status)
	}
}

// --- 5.9: CIDR ranges ---

func TestCheck_5_9_ScopedRanges(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "mydb", User: "appuser", Address: "10.0.1.0/24", Method: "scram-sha-256"},
	}

	c := &check_5_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for /24 range, got %s", result.Status)
	}
}

func TestCheck_5_9_UnrestrictedRange(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "scram-sha-256"},
	}

	c := &check_5_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for 0.0.0.0/0, got %s", result.Status)
	}
	if result.Severity != checker.SeverityCritical {
		t.Errorf("expected CRITICAL for 0.0.0.0/0, got %s", result.Severity)
	}
}

func TestCheck_5_9_LargeRange(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for /8 range, got %s", result.Status)
	}
	if result.Severity != checker.SeverityWarning {
		t.Errorf("expected WARNING for large range, got %s", result.Severity)
	}
}

// --- 5.10: specific databases and users ---

func TestCheck_5_10_SpecificEntries(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "mydb", User: "appuser", Address: "10.0.1.0/24", Method: "scram-sha-256"},
	}

	c := &check_5_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for specific db and user, got %s", result.Status)
	}
}

func TestCheck_5_10_AllDatabase(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "all", User: "appuser", Address: "10.0.1.0/24", Method: "scram-sha-256"},
	}

	c := &check_5_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for database='all', got %s", result.Status)
	}
}

func TestCheck_5_10_AllUser(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "mydb", User: "all", Address: "10.0.1.0/24", Method: "scram-sha-256"},
	}

	c := &check_5_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for user='all', got %s", result.Status)
	}
}

func TestCheck_5_10_RejectIgnored(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "reject"},
	}

	c := &check_5_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for reject entries, got %s", result.Status)
	}
}

// --- 5.11: superuser remote restriction ---

func TestCheck_5_11_SuperuserLocalOnly(t *testing.T) {
	_, env := newMockEnv(t)
	env.Superusers = []string{"postgres"}
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "local", Database: "all", User: "postgres", Method: "peer"},
		{LineNumber: 2, Type: "hostssl", Database: "mydb", User: "appuser", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_11{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_5_11_SuperuserRemoteAccess(t *testing.T) {
	_, env := newMockEnv(t)
	env.Superusers = []string{"postgres"}
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "all", User: "postgres", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_11{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for superuser remote access, got %s", result.Status)
	}
}

func TestCheck_5_11_AllUserRemote(t *testing.T) {
	_, env := newMockEnv(t)
	env.Superusers = []string{"postgres"}
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_11{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL when user='all' allows superuser remote, got %s", result.Status)
	}
}

// --- 5.12: password encryption ---

func TestCheck_5_12_ScramSHA256(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("password_encryption").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("scram-sha-256"))

	c := &check_5_12{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_5_12_MD5(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("password_encryption").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("md5"))

	c := &check_5_12{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for md5, got %s", result.Status)
	}
}

// --- 5.2: container/zalando accept * ---

func TestCheck_5_2_ContainerAcceptsStar(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformContainer
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("listen_addresses").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("*"))

	c := &check_5_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for listen_addresses=* on container, got %s", result.Status)
	}
}

func TestCheck_5_2_ZalandoAcceptsStar(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformZalando
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("listen_addresses").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("*"))

	c := &check_5_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for listen_addresses=* on zalando, got %s", result.Status)
	}
}

// --- 5.5: RDS role exclusion ---

func TestCheck_5_5_RDSRolesExcluded(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformRDS
	// On RDS the query adds a NOT IN clause, so we expect a different query
	mock.ExpectQuery("SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolconnlimit").
		WillReturnRows(pgxmock.NewRows([]string{"rolname"}))

	c := &check_5_5{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS when RDS roles excluded, got %s", result.Status)
	}
}

// --- 5.7: managed cloud auth_delay skip ---

func TestCheck_5_7_ManagedCloudSkipsAuthDelay(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformRDS
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("authentication_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("30"))

	c := &check_5_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// Should not FAIL because auth_delay check is skipped on RDS
	if result.Status == checker.StatusFail {
		t.Errorf("expected non-FAIL on RDS (auth_delay skipped), got FAIL")
	}
	// Should have info message about auth_delay being skipped
	found := false
	for _, msg := range result.Messages {
		if msg.Level == "INFO" && strings.Contains(msg.Content, "auth_delay") {
			found = true
		}
	}
	if !found {
		t.Error("expected INFO message about auth_delay being skipped on RDS")
	}
}

// --- parsePGInterval ---

func TestParsePGInterval(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"60", 60},
		{"30s", 30},
		{"2min", 120},
		{"1h", 3600},
		{"1d", 86400},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePGInterval(tt.input)
			if err != nil {
				t.Fatalf("parsePGInterval(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parsePGInterval(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// --- 5.3/5.4: mixed secure and insecure entries ---

func TestCheck_5_3_MixedAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "local", Database: "all", User: "all", Method: "peer"},
		{LineNumber: 2, Type: "local", Database: "all", User: "admin", Method: "trust"},
	}

	c := &check_5_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for mixed entries, got %s", result.Status)
	}
	// trust is forbidden → should be CRITICAL even though peer is secure
	if result.Severity != checker.SeverityCritical {
		t.Errorf("expected CRITICAL (worst wins), got %s", result.Severity)
	}
}

func TestCheck_5_4_MixedHostAuth(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "app", User: "app", Address: "10.0.0.0/8", Method: "scram-sha-256"},
		{LineNumber: 2, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "md5"},
	}

	c := &check_5_4{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for md5 host auth, got %s", result.Status)
	}
	if result.Severity != checker.SeverityWarning {
		t.Errorf("expected WARNING for md5, got %s", result.Severity)
	}
}

func TestCheck_5_3_IgnoresHostEntries(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "trust"},
		{LineNumber: 2, Type: "local", Database: "all", User: "all", Method: "peer"},
	}

	c := &check_5_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// check_5_3 only looks at local entries, so the trust host entry is ignored
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS (host entries ignored by 5.3), got %s", result.Status)
	}
}

// --- 5.8: localhost formats ---

func TestCheck_5_8_LocalhostFormats(t *testing.T) {
	localhostAddrs := []string{"127.0.0.1/32", "::1/128", "localhost", "127.0.0.1", "::1"}
	for _, addr := range localhostAddrs {
		t.Run(addr, func(t *testing.T) {
			_, env := newMockEnv(t)
			env.HBAEntries = []checker.HBAEntry{
				{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: addr, Method: "scram-sha-256"},
			}

			c := &check_5_8{}
			result, err := c.Run(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != checker.StatusPass {
				t.Errorf("expected PASS for localhost %q, got %s", addr, result.Status)
			}
		})
	}
}

func TestCheck_5_8_RejectIgnored(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "reject"},
	}

	c := &check_5_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for reject entries, got %s", result.Status)
	}
}

// --- 5.9: IPv6 and netmask edge cases ---

func TestCheck_5_9_IPv6Unrestricted(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "::/0", Method: "scram-sha-256"},
	}

	c := &check_5_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for ::/0, got %s", result.Status)
	}
	if result.Severity != checker.SeverityCritical {
		t.Errorf("expected CRITICAL for ::/0, got %s", result.Severity)
	}
}

func TestCheck_5_9_RejectIgnored(t *testing.T) {
	_, env := newMockEnv(t)
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "host", Database: "all", User: "all", Address: "0.0.0.0/0", Method: "reject"},
	}

	c := &check_5_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for reject entries, got %s", result.Status)
	}
}

// --- 5.11: multiple superusers ---

func TestCheck_5_11_MultipleSuperusers(t *testing.T) {
	_, env := newMockEnv(t)
	env.Superusers = []string{"postgres", "admin"}
	env.HBAEntries = []checker.HBAEntry{
		{LineNumber: 1, Type: "hostssl", Database: "all", User: "admin", Address: "10.0.0.0/8", Method: "scram-sha-256"},
	}

	c := &check_5_11{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for superuser 'admin' with remote access, got %s", result.Status)
	}
}

// --- networkSize ---

func TestNetworkSize(t *testing.T) {
	tests := []struct {
		addr string
		mask string
		want uint64
		ok   bool
	}{
		{"10.0.0.0/24", "", 256, true},
		{"10.0.0.0/32", "", 1, true},
		{"0.0.0.0/0", "", 1 << 32, true},
		{"10.0.0.0", "255.255.255.0", 256, true},
		{"invalid", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got, ok := networkSize(tt.addr, tt.mask)
			if ok != tt.ok {
				t.Fatalf("networkSize(%q, %q) ok=%v, want %v", tt.addr, tt.mask, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("networkSize(%q, %q) = %d, want %d", tt.addr, tt.mask, got, tt.want)
			}
		})
	}
}
