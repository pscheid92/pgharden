package section6

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

// --- 6.2: backend params ---

func TestCheck_6_2_AllSecure(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings WHERE context = 'backend'").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("ignore_system_indexes", "off").
			AddRow("jit_debugging_support", "off").
			AddRow("jit_profiling_support", "off").
			AddRow("log_connections", "on").
			AddRow("post_auth_delay", "0"))

	c := &check_6_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS, got %s", result.Status)
	}
}

func TestCheck_6_2_InsecureParam(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings WHERE context = 'backend'").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("ignore_system_indexes", "on").
			AddRow("log_connections", "off"))

	c := &check_6_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for insecure backend params, got %s", result.Status)
	}
}

// --- 6.3-6.6: context parameter checks ---

func TestContextParamCheck(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings WHERE context").
		WithArgs("postmaster").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("max_connections", "100").
			AddRow("port", "5432"))

	c := &contextParamCheck{id: "6.3", context: "postmaster"}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
	// Header + 2 params
	if len(result.Details) != 3 {
		t.Errorf("expected 3 detail rows, got %d", len(result.Details))
	}
}

// --- 6.8: TLS ---

func TestCheck_6_8_SSLOnTLS12(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("on"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_min_protocol_version").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("TLSv1.2"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_passphrase_command").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// ssl=on, TLSv1.2 → no failures
	if result.Status == checker.StatusFail {
		t.Errorf("expected non-FAIL for ssl=on, TLSv1.2, got FAIL")
	}
}

func TestCheck_6_8_SSLOff(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_min_protocol_version").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("TLSv1.2"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_passphrase_command").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for ssl=off, got %s", result.Status)
	}
}

func TestCheck_6_8_WeakTLS(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("on"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_min_protocol_version").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("TLSv1"))
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_passphrase_command").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for TLSv1, got %s", result.Status)
	}
}

// --- 6.9: crypto extensions ---

func TestCheck_6_9_CryptoAvailable(t *testing.T) {
	mock, env := newMockEnv(t)
	installed := "1.3"
	defaultVer := "1.3"
	mock.ExpectQuery("SELECT name, installed_version, default_version FROM pg_available_extensions").
		WillReturnRows(pgxmock.NewRows([]string{"name", "installed_version", "default_version"}).
			AddRow("pgcrypto", &installed, &defaultVer))

	c := &check_6_9{}
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

func TestCheck_6_9_NoCryptoExtensions(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, installed_version, default_version FROM pg_available_extensions").
		WillReturnRows(pgxmock.NewRows([]string{"name", "installed_version", "default_version"}))

	c := &check_6_9{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
}

// --- 6.10: SSL ciphers ---

func TestCheck_6_10_AllowedCiphers(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_ciphers").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).
			AddRow("TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384"))

	c := &check_6_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS for allowed ciphers, got %s", result.Status)
	}
}

func TestCheck_6_10_DisallowedCiphers(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl_ciphers").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).
			AddRow("TLS_AES_256_GCM_SHA384:DES-CBC3-SHA"))

	c := &check_6_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for disallowed cipher, got %s", result.Status)
	}
}

// --- 6.11: anonymization ---

func TestCheck_6_11_AnonConfigured(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("session_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("anon"))

	c := &check_6_11{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS with anon, got %s", result.Status)
	}
}

func TestCheck_6_11_NoAnon(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("session_preload_libraries").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(""))

	c := &check_6_11{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL without anon, got %s", result.Status)
	}
}

// --- 6.8: managed cloud SSL ---

func TestCheck_6_8_ManagedCloudSkipsProtocolVersion(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformRDS
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("on"))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// Should not FAIL — ssl is on, and protocol version is managed by AWS
	if result.Status == checker.StatusFail {
		t.Errorf("expected non-FAIL on RDS with ssl=on, got FAIL")
	}
	found := false
	for _, msg := range result.Messages {
		if msg.Content == "ssl_min_protocol_version managed by AWS" {
			found = true
		}
	}
	if !found {
		t.Error("expected message about ssl_min_protocol_version being managed by AWS")
	}
}

func TestCheck_6_8_ManagedCloudSSLOff(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = checker.PlatformAurora
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusFail {
		t.Errorf("expected FAIL for ssl=off even on Aurora, got %s", result.Status)
	}
}

// --- 6.10: managed cloud ciphers ---

func TestCheck_6_10_ManagedCloudPassesCiphers(t *testing.T) {
	_, env := newMockEnv(t)
	env.Platform = checker.PlatformRDS

	c := &check_6_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != checker.StatusPass {
		t.Errorf("expected PASS on RDS (ciphers managed by AWS), got %s", result.Status)
	}
}
