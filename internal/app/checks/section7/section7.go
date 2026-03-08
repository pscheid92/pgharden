package section7

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pscheid92/pgharden/internal/domain"
)

func Checks() []domain.Check {
	return []domain.Check{
		&check_7_1{},
		&domain.SettingCheck{
			CheckID: "7.2", Setting: "log_replication_commands", Expected: "on",
			Sev: domain.SeverityWarning, Reqs: domain.CheckRequirements{SQLOnly: true},
			Ref: domain.CISRef("7.2"),
		}, // 7.2 runs on all platforms per matrix
		&check_7_4{},
		&check_7_5{},
	}
}

type check_7_1 struct{}

func (c *check_7_1) ID() string { return "7.1" }

func (c *check_7_1) Reference() *domain.Reference { return domain.CISRef("7.1") }

func (c *check_7_1) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true, SkipPlatforms: []string{domain.PlatformAurora}}
}

func (c *check_7_1) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	// On RDS, rds_replication role serves as the dedicated replication mechanism
	if env.Platform == domain.PlatformRDS {
		return c.checkRDS(ctx, env)
	}

	rows, err := env.DB.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolreplication = true")
	if err != nil {
		return nil, err
	}
	replUsers, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	result := domain.NewResult(domain.SeverityWarning)

	if len(replUsers) == 0 {
		result.Fail("No dedicated replication user found (no roles with REPLICATION privilege)")
		return result, nil
	}

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

func (c *check_7_1) checkRDS(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	var count int
	if err := env.DB.QueryRow(ctx, "SELECT COUNT(*) FROM pg_roles WHERE rolname = 'rds_replication'").Scan(&count); err != nil {
		return nil, err
	}

	result := domain.NewResult(domain.SeverityWarning)
	if count > 0 {
		result.Pass("rds_replication role exists (RDS dedicated replication mechanism)")
	} else {
		result.Fail("rds_replication role not found on RDS")
	}
	return result, nil
}

type check_7_4 struct{}

func (c *check_7_4) ID() string { return "7.4" }

func (c *check_7_4) Reference() *domain.Reference { return domain.CISRef("7.4") }

func (c *check_7_4) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true, SkipPlatforms: domain.ManagedCloud}
}

func (c *check_7_4) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
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

	result := &domain.CheckResult{Severity: domain.SeverityWarning, Details: details}

	archiveMode, ok := settings["archive_mode"]
	if !ok || archiveMode == "off" {
		result.Fail("archive_mode is not enabled")
	} else {
		result.Pass("archive_mode is '" + archiveMode + "'")
	}
	return result, nil
}

type check_7_5 struct{}

func (c *check_7_5) ID() string { return "7.5" }

func (c *check_7_5) Reference() *domain.Reference { return domain.CISRef("7.5") }

func (c *check_7_5) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true, SkipPlatforms: domain.ManagedCloud}
}

func (c *check_7_5) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	val, err := domain.ShowSetting(ctx, env.DB, "primary_conninfo")
	if errors.Is(err, domain.ErrPermissionDenied) {
		return domain.SkippedPermission("primary_conninfo"), nil
	}
	if err != nil {
		return nil, err
	}

	result := domain.NewResult(domain.SeverityWarning)

	if val == "" {
		result.Pass("primary_conninfo is not set (this server is not a replica)")
		return result, nil
	}

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
				result.Info("primary_conninfo sslmode is '" + value + "'")
			}
		}
		if key == "sslcompression" {
			hasSSLCompression = true
			if value != "1" {
				result.Warn("primary_conninfo sslcompression is '" + value + "', expected '1'")
			} else {
				result.Info("primary_conninfo sslcompression is enabled")
			}
		}
	}

	if !hasSSLMode {
		result.Fail("primary_conninfo does not specify sslmode")
	}

	if !hasSSLCompression {
		result.Warn("primary_conninfo does not specify sslcompression")
	}

	if result.Status != domain.StatusFail {
		result.Status = domain.StatusPass
	}

	return result, nil
}
