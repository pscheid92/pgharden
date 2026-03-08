package section8

import (
	"context"
	"fmt"
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

func TestCheck_8_3_SpecialSettings(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("ssl_cert_file", "/etc/ssl/certs/server.crt").
			AddRow("ssl_key_file", "/etc/ssl/private/server.key").
			AddRow("hba_file", "/etc/postgresql/16/main/pg_hba.conf"))

	c := &check_8_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
	// Header + 3 settings
	if len(result.Details) != 4 {
		t.Errorf("expected 4 detail rows (header + 3), got %d", len(result.Details))
	}
}

func TestCheck_8_3_NoSettings(t *testing.T) {
	mock, env := newMockEnv(t)
	mock.ExpectQuery("SELECT name, setting FROM pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}))

	c := &check_8_3{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusManual {
		t.Errorf("expected MANUAL, got %s", result.Status)
	}
}

// --- 8.2: pgBackRest ---

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

func TestCheck_8_2_StanzaConfigured(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"pgbackrest": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{
			"pgbackrest info": "stanza: main\n  status: ok\n",
		},
	}

	c := &check_8_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusPass {
		t.Errorf("expected PASS for configured pgbackrest, got %s", result.Status)
	}
}

func TestCheck_8_2_NoStanza(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"pgbackrest": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{
			"pgbackrest info": "No stanzas exist in the repository.\n",
		},
	}

	c := &check_8_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for no stanzas, got %s", result.Status)
	}
}

func TestCheck_8_2_CommandFails(t *testing.T) {
	_, env := newMockEnv(t)
	env.Commands = map[string]bool{"pgbackrest": true}
	env.Cmd = &mockCmd{
		outputs: map[string]string{
			"pgbackrest info": "ERROR: unable to load info",
		},
		errors: map[string]error{
			"pgbackrest info": fmt.Errorf("exit status 1"),
		},
	}

	c := &check_8_2{}
	result, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.StatusFail {
		t.Errorf("expected FAIL for command error, got %s", result.Status)
	}
}
