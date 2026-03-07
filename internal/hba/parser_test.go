package hba

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLineLocal(t *testing.T) {
	e, ok := parseLine("local all all peer", 1)
	if !ok {
		t.Fatal("parseLine returned false")
	}
	if e.Type != "local" || e.Database != "all" || e.User != "all" || e.Method != "peer" {
		t.Errorf("unexpected entry: %+v", e)
	}
	if e.LineNumber != 1 {
		t.Errorf("line number = %d, want 1", e.LineNumber)
	}
}

func TestParseLineHost(t *testing.T) {
	e, ok := parseLine("host all all 192.168.1.0/24 scram-sha-256", 5)
	if !ok {
		t.Fatal("parseLine returned false")
	}
	if e.Type != "host" || e.Address != "192.168.1.0/24" || e.Method != "scram-sha-256" {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestParseLineHostSSL(t *testing.T) {
	e, ok := parseLine("hostssl replication repuser 10.0.0.0/8 cert", 10)
	if !ok {
		t.Fatal("parseLine returned false")
	}
	if e.Type != "hostssl" || e.Database != "replication" || e.User != "repuser" || e.Method != "cert" {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestParseLineWithNetmask(t *testing.T) {
	e, ok := parseLine("host all all 192.168.1.0 255.255.255.0 md5", 3)
	if !ok {
		t.Fatal("parseLine returned false")
	}
	if e.Address != "192.168.1.0" || e.Netmask != "255.255.255.0" || e.Method != "md5" {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestParseLineTooShort(t *testing.T) {
	_, ok := parseLine("local all", 1)
	if ok {
		t.Error("parseLine should return false for too-short line")
	}
}

func TestParseLineWithOptions(t *testing.T) {
	e, ok := parseLine("host all all 0.0.0.0/0 ldap ldapserver=ldap.example.com", 1)
	if !ok {
		t.Fatal("parseLine returned false")
	}
	if e.Method != "ldap" || e.Options != "ldapserver=ldap.example.com" {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestAuthMethods(t *testing.T) {
	for _, m := range []string{"trust", "reject", "scram-sha-256", "md5", "peer", "cert"} {
		if !authMethods[m] {
			t.Errorf("expected %q to be an auth method", m)
		}
	}
	if authMethods["192.168.1.0"] {
		t.Error("IP address should not be an auth method")
	}
	if authMethods["255.255.255.0"] {
		t.Error("netmask should not be an auth method")
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `# Comment
local all all peer
host all all 127.0.0.1/32 scram-sha-256
host all all ::1/128 scram-sha-256
`
	dir := t.TempDir()
	path := filepath.Join(dir, "pg_hba.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := LoadFromFile(os.DirFS("/"), path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Type != "local" {
		t.Errorf("first entry type = %q, want local", entries[0].Type)
	}
}

func TestLoadFromFileInclude(t *testing.T) {
	dir := t.TempDir()

	// Create included file
	incContent := "host mydb myuser 10.0.0.0/8 scram-sha-256\n"
	incPath := filepath.Join(dir, "extra.conf")
	if err := os.WriteFile(incPath, []byte(incContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main file
	mainContent := "local all all peer\ninclude " + incPath + "\n"
	mainPath := filepath.Join(dir, "pg_hba.conf")
	if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := LoadFromFile(os.DirFS("/"), mainPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[1].Database != "mydb" {
		t.Errorf("included entry db = %q, want mydb", entries[1].Database)
	}
}
