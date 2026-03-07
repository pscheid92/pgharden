package section7

import (
	"context"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
)

// Checks returns all Section 7 checks.
func Checks() []checker.Check {
	return []checker.Check{
		&check_7_1{},
		&checker.SettingCheck{
			CheckID: "7.2", Setting: "log_replication_commands", Expected: "on",
			Sev: checker.SeverityWarning, Reqs: checker.CheckRequirements{SQLOnly: true},
		},
		&check_7_4{},
		&check_7_5{},
	}
}

// check_7_1 - Dedicated replication user
type check_7_1 struct{}

func (c *check_7_1) ID() string { return "7.1" }

func (c *check_7_1) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_7_1) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolreplication = true")
	if err != nil {
		return nil, err
	}
	replUsers, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	result := checker.NewResult(checker.SeverityWarning)

	if len(replUsers) == 0 {
		result.Fail("No dedicated replication user found (no roles with REPLICATION privilege)")
		return result, nil
	}

	// Check if the only replication user is a superuser (bad practice)
	hasDedicated := false
	for _, u := range replUsers {
		isSuperuser := slices.Contains(env.Superusers, u)
		if !isSuperuser {
			hasDedicated = true
		}
	}

	details := [][]string{{"Role", "Type"}}
	for _, u := range replUsers {
		roleType := "dedicated replication"
		if slices.Contains(env.Superusers, u) {
			roleType = "superuser"
		}
		details = append(details, []string{u, roleType})
	}
	result.Details = details

	if hasDedicated {
		result.Pass("Dedicated replication user(s) found")
	} else {
		result.Fail("Only superuser accounts have REPLICATION privilege; a dedicated replication user should be created")
	}
	return result, nil
}

// check_7_4 - Archive mode
type check_7_4 struct{}

func (c *check_7_4) ID() string { return "7.4" }

func (c *check_7_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_7_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, "SELECT name, setting FROM pg_settings WHERE name ~ '^archive'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	details := [][]string{{"Setting", "Value"}}
	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			return nil, err
		}
		settings[name] = setting
		details = append(details, []string{name, setting})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning, Details: details}

	archiveMode, ok := settings["archive_mode"]
	if !ok || archiveMode == "off" {
		result.Fail("archive_mode is not enabled")
	} else {
		result.Pass("archive_mode is '" + archiveMode + "'")
	}
	return result, nil
}

// check_7_5 - Replication SSL
type check_7_5 struct{}

func (c *check_7_5) ID() string { return "7.5" }

func (c *check_7_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_7_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "primary_conninfo")
	if err != nil {
		return nil, err
	}

	result := checker.NewResult(checker.SeverityWarning)

	if val == "" {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: "primary_conninfo is not set (this server is not a replica)",
		})
		return result, nil
	}

	// Parse the connection string for SSL settings
	hasSSLMode := false
	hasSSLCompression := false
	for part := range strings.FieldsSeq(val) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		if key == "sslmode" {
			hasSSLMode = true
			if value != "require" && value != "verify-ca" && value != "verify-full" {
				result.Fail("primary_conninfo sslmode is '"+value+"', expected 'require', 'verify-ca', or 'verify-full'")
			} else {
				result.Messages = append(result.Messages, checker.Message{
					Level:   "SUCCESS",
					Content: "primary_conninfo sslmode is '" + value + "'",
				})
			}
		}
		if key == "sslcompression" {
			hasSSLCompression = true
			if value != "1" {
				result.Warn("primary_conninfo sslcompression is '" + value + "', expected '1'")
			} else {
				result.Messages = append(result.Messages, checker.Message{
					Level:   "SUCCESS",
					Content: "primary_conninfo sslcompression is enabled",
				})
			}
		}
	}

	if !hasSSLMode {
		result.Fail("primary_conninfo does not specify sslmode")
	}

	if !hasSSLCompression {
		result.Warn("primary_conninfo does not specify sslcompression")
	}

	// Set overall status if not already failed
	if result.Status != checker.StatusFail {
		result.Status = checker.StatusPass
	}

	return result, nil
}
