package section8

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

func init() {
	checker.Register(&check82{})
	checker.Register(&check8_3{})
}

// check82 - pgBackRest backup
type check82 struct{}

func (c *check82) ID() string { return "8.2" }

func (c *check82) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"pgbackrest"}}
}

func (c *check82) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	out, err := exec.CommandContext(ctx, "pgbackrest", "info").CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "pgBackRest info failed: " + output,
		})
		return result, nil
	}

	if strings.Contains(output, "stanza:") || strings.Contains(output, "status:") {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "pgBackRest is configured with active stanza(s)",
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "pgBackRest is installed but no stanzas found",
		})
	}
	return result, nil
}

// check8_3 - Special file settings
type check8_3 struct{}

func (c *check8_3) ID() string { return "8.3" }

func (c *check8_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check8_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
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

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
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
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d settings referencing external files and programs. Review for security.", count),
	})

	return result, nil
}
