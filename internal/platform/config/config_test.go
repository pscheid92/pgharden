package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Host != "localhost" {
		t.Errorf("Host = %q, want localhost", cfg.Host)
	}
	if cfg.Port != 5432 {
		t.Errorf("Port = %d, want 5432", cfg.Port)
	}
	if cfg.User != "postgres" {
		t.Errorf("User = %q, want postgres", cfg.User)
	}
	if cfg.Database != "postgres" {
		t.Errorf("Database = %q, want postgres", cfg.Database)
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Format)
	}
}

func TestConnString(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		cfg := DefaultConfig()
		s := cfg.ConnString()
		if s != "host=localhost port=5432 user=postgres dbname=postgres sslmode=prefer" {
			t.Errorf("ConnString = %q", s)
		}
	})

	t.Run("dsn_override", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DSN = "postgres://user:pass@host/db"
		if cfg.ConnString() != cfg.DSN {
			t.Errorf("DSN should override, got %q", cfg.ConnString())
		}
	})
}

func TestLoadFile(t *testing.T) {
	yaml := `
host: myhost
port: 5433
user: myuser
database: mydb
format: html
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	if err := cfg.LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.Host != "myhost" {
		t.Errorf("Host = %q, want myhost", cfg.Host)
	}
	if cfg.Port != 5433 {
		t.Errorf("Port = %d, want 5433", cfg.Port)
	}
	if cfg.Format != "html" {
		t.Errorf("Format = %q, want html", cfg.Format)
	}
}

func TestLoadFileProfile(t *testing.T) {
	yaml := `
profile: minimal
profiles:
  minimal:
    include_section: "1"
    exclude_checks:
      - "1.5"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	if err := cfg.LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.IncludeSection != "1" {
		t.Errorf("IncludeSection = %q, want 1", cfg.IncludeSection)
	}
	if len(cfg.ExcludeChecks) != 1 || cfg.ExcludeChecks[0] != "1.5" {
		t.Errorf("ExcludeChecks = %v, want [1.5]", cfg.ExcludeChecks)
	}
}

func TestLoadFileInvalidProfile(t *testing.T) {
	yaml := `profile: nonexistent
profiles:
  other:
    include_section: "1"`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	err := cfg.LoadFile(path)
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}
