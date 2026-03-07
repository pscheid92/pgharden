package config

import (
	"fmt"
	"os"

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
	Format string `yaml:"format"` // json, html
	Output string `yaml:"output"` // Output file path, empty for stdout.
	Title  string `yaml:"title"`
	Lang   string `yaml:"lang"` // en_US, fr_FR, zh_CN

	// Filtering
	IncludeChecks  []string `yaml:"include_checks"`
	ExcludeChecks  []string `yaml:"exclude_checks"`
	IncludeSection string   `yaml:"include_section"`

	// Database filtering
	AllowDatabases   []string `yaml:"allow_databases"`
	ExcludeDatabases []string `yaml:"exclude_databases"`

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
		Lang:     "en_US",
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

func (c *Config) ConnString() string {
	if c.DSN != "" {
		return c.DSN
	}

	return fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=prefer", c.Host, c.Port, c.User, c.Database)
}
