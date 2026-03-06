package section7

import (
	"context"
	"slices"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

func init() {
	checker.Register(&check_7_1{})
	checker.Register(&checker.SettingCheck{
		CheckID: "7.2", Setting: "log_replication_commands", Expected: "on",
		Sev: checker.SeverityWarning, Reqs: checker.CheckRequirements{SQLOnly: true},
	})
	checker.Register(&check_7_4{})
	checker.Register(&check_7_5{})
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
	defer rows.Close()

	var replUsers []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		replUsers = append(replUsers, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	if len(replUsers) == 0 {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "No dedicated replication user found (no roles with REPLICATION privilege)",
		})
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
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "Dedicated replication user(s) found",
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Only superuser accounts have REPLICATION privilege; a dedicated replication user should be created",
		})
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
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "archive_mode is not enabled",
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "archive_mode is '" + archiveMode + "'",
		})
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
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW primary_conninfo").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

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
				result.Status = checker.StatusFail
				result.Messages = append(result.Messages, checker.Message{
					Level:   "FAILURE",
					Content: "primary_conninfo sslmode is '" + value + "', expected 'require', 'verify-ca', or 'verify-full'",
				})
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
				result.Messages = append(result.Messages, checker.Message{
					Level:   "WARNING",
					Content: "primary_conninfo sslcompression is '" + value + "', expected '1'",
				})
			} else {
				result.Messages = append(result.Messages, checker.Message{
					Level:   "SUCCESS",
					Content: "primary_conninfo sslcompression is enabled",
				})
			}
		}
	}

	if !hasSSLMode {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "primary_conninfo does not specify sslmode",
		})
	}

	if !hasSSLCompression {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "WARNING",
			Content: "primary_conninfo does not specify sslcompression",
		})
	}

	// Set overall status if not already failed
	if result.Status != checker.StatusFail {
		result.Status = checker.StatusPass
	}

	return result, nil
}
