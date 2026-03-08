package config

import (
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgconn"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Connection
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Database string `yaml:"database"`
	DSN      string `yaml:"dsn"` // Full connection string (overrides individual fields).

	// Output
	Format string `yaml:"format"` // text, json, html
	Output string `yaml:"output"` // Output file path, empty for stdout.
	Title  string `yaml:"title"`
	// Filtering
	IncludeChecks  []string `yaml:"include_checks"`
	ExcludeChecks  []string `yaml:"exclude_checks"`
	IncludeSection string   `yaml:"include_section"`
	IncludeSource  string   `yaml:"include_source"`

	// Database filtering
	AllowDatabases   []string `yaml:"allow_databases"`
	ExcludeDatabases []string `yaml:"exclude_databases"`

	// Environment
	Platform string `yaml:"platform"` // Override auto-detected platform (bare-metal, container, kubernetes, rds, aurora).
	Local    bool   `yaml:"local"`    // Enable filesystem and command checks (only when running on the PG host).

	// Profiles
	Profile  string              `yaml:"profile"`
	Profiles map[string]*Profile `yaml:"profiles"`
}

type Profile struct {
	IncludeChecks  []string `yaml:"include_checks"`
	ExcludeChecks  []string `yaml:"exclude_checks"`
	IncludeSection string   `yaml:"include_section"`
}

func DefaultConfig() *Config {
	return &Config{
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Database: "postgres",
		Format:   "json",
	}
}

func (c *Config) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("parsing config file: %w", err)
	}

	if c.Profile == "" || c.Profiles == nil {
		return nil
	}

	p, ok := c.Profiles[c.Profile]
	if !ok {
		return fmt.Errorf("profile %q not found in config", c.Profile)
	}

	if len(p.IncludeChecks) > 0 {
		c.IncludeChecks = p.IncludeChecks
	}
	if len(p.ExcludeChecks) > 0 {
		c.ExcludeChecks = p.ExcludeChecks
	}
	if p.IncludeSection != "" {
		c.IncludeSection = p.IncludeSection
	}

	return nil
}

// ResolveDSN parses a DSN string and backfills Host, Port, User, Database
// so that log messages and report metadata reflect the actual connection target.
func (c *Config) ResolveDSN() error {
	if c.DSN == "" {
		return nil
	}
	cfg, err := pgconn.ParseConfig(c.DSN)
	if err != nil {
		return fmt.Errorf("parsing DSN: %w", err)
	}
	c.Host = cfg.Host
	c.Port = int(cfg.Port)
	c.User = cfg.User
	c.Database = cfg.Database
	return nil
}

func (c *Config) ConnString() string {
	if c.DSN != "" {
		return c.DSN
	}

	return fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=prefer", c.Host, c.Port, c.User, c.Database)
}
