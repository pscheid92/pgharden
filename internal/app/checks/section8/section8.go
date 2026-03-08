package section8

import (
	"context"
	"fmt"
	"strings"

	"github.com/pscheid92/pgharden/internal/domain"
)

func Checks() []domain.Check {
	return []domain.Check{
		&check_8_2{},
		&check_8_3{},
	}
}

type check_8_2 struct{}

func (c *check_8_2) ID() string { return "8.2" }

func (c *check_8_2) Reference() *domain.Reference { return domain.CISRef("8.2") }

func (c *check_8_2) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Commands: []string{"pgbackrest"}, SkipPlatforms: []string{domain.PlatformKubernetes, domain.PlatformRDS, domain.PlatformAurora}}
}

func (c *check_8_2) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	out, err := env.GetCmd().Run(ctx, "pgbackrest", "info")
	output := strings.TrimSpace(string(out))

	if err != nil {
		result.Fail("pgBackRest info failed: "+output)
		return result, nil
	}

	if strings.Contains(output, "stanza:") || strings.Contains(output, "status:") {
		result.Pass("pgBackRest is configured with active stanza(s)")
	} else {
		result.Fail("pgBackRest is installed but no stanzas found")
	}
	return result, nil
}

type check_8_3 struct{}

func (c *check_8_3) ID() string { return "8.3" }

func (c *check_8_3) Reference() *domain.Reference { return domain.CISRef("8.3") }

func (c *check_8_3) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_8_3) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT name, setting FROM pg_settings
		WHERE name IN ('ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_crl_file',
			'hba_file', 'ident_file', 'shared_preload_libraries',
			'session_preload_libraries', 'local_preload_libraries',
			'dynamic_library_path', 'ssl_passphrase_command', 'archive_command')
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("query special file settings: %w", err)
	}
	defer rows.Close()

	result := &domain.CheckResult{
		Status:   domain.StatusManual,
		Severity: domain.SeverityInfo,
	}

	details := [][]string{{"Parameter", "Value"}}
	count := 0
	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			return nil, fmt.Errorf("scan setting: %w", err)
		}
		details = append(details, []string{name, setting})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate settings: %w", err)
	}

	result.Details = details
	result.Info(fmt.Sprintf("Found %d settings referencing external files and programs. Review for security.", count))

	return result, nil
}
