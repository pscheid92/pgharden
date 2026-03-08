package section6

import (
	"context"
	"testing"

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
	if result.Status != domain.StatusPass {
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
	if result.Status != domain.StatusFail {
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
	if result.Status != domain.StatusManual {
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
	if result.Status == domain.StatusFail {
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
	if result.Status != domain.StatusFail {
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
	if result.Status != domain.StatusFail {
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
	if result.Status != domain.StatusManual {
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
	if result.Status != domain.StatusManual {
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
	if result.Status != domain.StatusPass {
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
	if result.Status != domain.StatusFail {
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
	if result.Status != domain.StatusPass {
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
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL without anon, got %s", result.Status)
	}
}

// --- 6.8: managed cloud SSL ---

func TestCheck_6_8_ManagedCloudSkipsProtocolVersion(t *testing.T) {
	mock, env := newMockEnv(t)
	env.Platform = domain.PlatformRDS
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("on"))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// Should not FAIL — ssl is on, and protocol version is managed by AWS
	if result.Status == domain.StatusFail {
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
	env.Platform = domain.PlatformAurora
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("ssl").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("off"))

	c := &check_6_8{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for ssl=off even on Aurora, got %s", result.Status)
	}
}

// --- 6.10: managed cloud ciphers ---

func TestCheck_6_10_ManagedCloudPassesCiphers(t *testing.T) {
	_, env := newMockEnv(t)
	env.Platform = domain.PlatformRDS

	c := &check_6_10{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS on RDS (ciphers managed by AWS), got %s", result.Status)
	}
}

// --- 6.12-6.14: timeout settings ---

func TestCheck_6_12_IdleInTransactionTimeout_Configured(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("idle_in_transaction_session_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("60000"))

	checks := Checks()
	var check domain.Check
	for _, c := range checks {
		if c.ID() == "6.12" {
			check = c
			break
		}
	}
	result, err := check.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for non-zero idle_in_transaction_session_timeout, got %s", result.Status)
	}
}

func TestCheck_6_12_IdleInTransactionTimeout_Disabled(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("idle_in_transaction_session_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("0"))

	checks := Checks()
	var check domain.Check
	for _, c := range checks {
		if c.ID() == "6.12" {
			check = c
			break
		}
	}
	result, err := check.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for disabled idle_in_transaction_session_timeout, got %s", result.Status)
	}
}

func TestCheck_6_13_StatementTimeout_Configured(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("statement_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("30000"))

	checks := Checks()
	var check domain.Check
	for _, c := range checks {
		if c.ID() == "6.13" {
			check = c
			break
		}
	}
	result, err := check.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for non-zero statement_timeout, got %s", result.Status)
	}
}

func TestCheck_6_14_LockTimeout_Disabled(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT setting FROM pg_settings").
		WithArgs("lock_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow("0"))

	checks := Checks()
	var check domain.Check
	for _, c := range checks {
		if c.ID() == "6.14" {
			check = c
			break
		}
	}
	result, err := check.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for disabled lock_timeout, got %s", result.Status)
	}
}

// --- 6.7: FIPS mode ---

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

func TestCheck_6_7_FIPSEnabled(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"fips-mode-setup": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{
			"fips-mode-setup --check": "FIPS mode is enabled.",
		},
	}

	c := &check_6_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for FIPS enabled, got %s", result.Status)
	}
}

func TestCheck_6_7_FIPSDisabled(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"fips-mode-setup": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{
			"fips-mode-setup --check": "FIPS mode is disabled.",
		},
	}

	c := &check_6_7{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for FIPS disabled, got %s", result.Status)
	}
}
