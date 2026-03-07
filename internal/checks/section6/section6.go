package section6

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

// Checks returns all Section 6 checks.
func Checks() []checker.Check {
	return []checker.Check{
		&check_6_2{},
		&check_6_3{},
		&check_6_4{},
		&check_6_5{},
		&check_6_6{},
		&check_6_7{},
		&check_6_8{},
		&check_6_9{},
		&check_6_10{},
		&check_6_11{},
	}
}

// check_6_2 - Backend runtime parameters
type check_6_2 struct{}

func (c *check_6_2) ID() string { return "6.2" }

func (c *check_6_2) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_2) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT name, setting FROM pg_settings WHERE context = 'backend'")
	if err != nil {
		return nil, fmt.Errorf("query backend parameters: %w", err)
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			return nil, fmt.Errorf("scan backend parameter: %w", err)
		}
		settings[name] = setting
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate backend parameters: %w", err)
	}

	expected := map[string]string{
		"ignore_system_indexes": "off",
		"jit_debugging_support": "off",
		"jit_profiling_support": "off",
		"log_connections":       "on",
		"post_auth_delay":       "0",
	}

	result := checker.NewResult(checker.SeverityWarning)
	details := [][]string{{"Parameter", "Current Value", "Expected Value", "Status"}}
	failed := false

	for param, want := range expected {
		got, exists := settings[param]
		if !exists {
			continue
		}
		status := "OK"
		if got != want {
			status = "FAIL"
			failed = true
		}
		details = append(details, []string{param, got, want, status})
	}

	result.Details = details

	if failed {
		result.FailWarn("One or more backend runtime parameters have insecure values.")
	} else {
		result.Pass("All checked backend runtime parameters have secure values.")
	}

	return result, nil
}

// check_6_3 - Postmaster runtime parameters
type check_6_3 struct{}

func (c *check_6_3) ID() string { return "6.3" }

func (c *check_6_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT name, setting FROM pg_settings WHERE context = 'postmaster' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("query postmaster parameters: %w", err)
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
			return nil, fmt.Errorf("scan parameter: %w", err)
		}
		details = append(details, []string{name, setting})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate parameters: %w", err)
	}

	result.Details = details
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d postmaster context parameters. Review for appropriate configuration.", count),
	})

	return result, nil
}

// check_6_4 - SIGHUP runtime parameters
type check_6_4 struct{}

func (c *check_6_4) ID() string { return "6.4" }

func (c *check_6_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT name, setting FROM pg_settings WHERE context = 'sighup' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("query sighup parameters: %w", err)
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
			return nil, fmt.Errorf("scan parameter: %w", err)
		}
		details = append(details, []string{name, setting})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate parameters: %w", err)
	}

	result.Details = details
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d sighup context parameters. Review for appropriate configuration.", count),
	})

	return result, nil
}

// check_6_5 - Superuser runtime parameters
type check_6_5 struct{}

func (c *check_6_5) ID() string { return "6.5" }

func (c *check_6_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT name, setting FROM pg_settings WHERE context = 'superuser' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("query superuser parameters: %w", err)
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
			return nil, fmt.Errorf("scan parameter: %w", err)
		}
		details = append(details, []string{name, setting})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate parameters: %w", err)
	}

	result.Details = details
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d superuser context parameters. Review for appropriate configuration.", count),
	})

	return result, nil
}

// check_6_6 - User runtime parameters
type check_6_6 struct{}

func (c *check_6_6) ID() string { return "6.6" }

func (c *check_6_6) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_6) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT name, setting FROM pg_settings WHERE context = 'user' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("query user parameters: %w", err)
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
			return nil, fmt.Errorf("scan parameter: %w", err)
		}
		details = append(details, []string{name, setting})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate parameters: %w", err)
	}

	result.Details = details
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d user context parameters. Review for appropriate configuration.", count),
	})

	return result, nil
}

// check_6_7 - FIPS mode
type check_6_7 struct{}

func (c *check_6_7) ID() string { return "6.7" }

func (c *check_6_7) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"fips-mode-setup"}}
}

func (c *check_6_7) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityWarning)

	out, err := exec.CommandContext(ctx, "fips-mode-setup", "--check").CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		result.Fail("FIPS mode check failed: "+output)
		return result, nil
	}

	if strings.Contains(strings.ToLower(output), "enabled") {
		result.Pass("FIPS mode is enabled: " + output)
	} else {
		result.Fail("FIPS mode is not enabled: "+output)
	}
	return result, nil
}

// check_6_8 - SSL settings
type check_6_8 struct{}

func (c *check_6_8) ID() string { return "6.8" }

func (c *check_6_8) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_8) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var sslOn, sslMinVersion, sslPassCmd string

	err := env.DB.QueryRow(ctx, "SHOW ssl").Scan(&sslOn)
	if err != nil {
		return nil, fmt.Errorf("query ssl: %w", err)
	}

	err = env.DB.QueryRow(ctx, "SHOW ssl_min_protocol_version").Scan(&sslMinVersion)
	if err != nil {
		return nil, fmt.Errorf("query ssl_min_protocol_version: %w", err)
	}

	err = env.DB.QueryRow(ctx, "SHOW ssl_passphrase_command").Scan(&sslPassCmd)
	if err != nil {
		return nil, fmt.Errorf("query ssl_passphrase_command: %w", err)
	}

	result := checker.NewResult(checker.SeverityCritical)
	failed := false

	if sslOn != "on" {
		failed = true
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: fmt.Sprintf("ssl is '%s' (should be 'on').", sslOn),
		})
	} else {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "ssl is enabled.",
		})
	}

	if sslMinVersion != "TLSv1.2" && sslMinVersion != "TLSv1.3" {
		failed = true
		result.Messages = append(result.Messages, checker.Message{
			Level:   "WARNING",
			Content: fmt.Sprintf("ssl_min_protocol_version is '%s' (should be 'TLSv1.2' or 'TLSv1.3').", sslMinVersion),
		})
	} else {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: fmt.Sprintf("ssl_min_protocol_version is '%s'.", sslMinVersion),
		})
	}

	if sslPassCmd != "" {
		result.Info(fmt.Sprintf("ssl_passphrase_command is configured: '%s'.", sslPassCmd))
	}

	if failed {
		result.Status = checker.StatusFail
	} else {
		result.Status = checker.StatusPass
	}

	return result, nil
}

// check_6_9 - Cryptographic extensions
type check_6_9 struct{}

func (c *check_6_9) ID() string { return "6.9" }

func (c *check_6_9) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_9) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT name, installed_version, default_version FROM pg_available_extensions WHERE name IN ('pgcrypto', 'pgsodium')")
	if err != nil {
		return nil, fmt.Errorf("query crypto extensions: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
	}

	details := [][]string{{"Extension", "Installed Version", "Default Version"}}
	count := 0
	for rows.Next() {
		var name string
		var installed, defaultVer *string
		if err := rows.Scan(&name, &installed, &defaultVer); err != nil {
			return nil, fmt.Errorf("scan extension: %w", err)
		}
		instStr := "not installed"
		if installed != nil {
			instStr = *installed
		}
		defStr := ""
		if defaultVer != nil {
			defStr = *defaultVer
		}
		details = append(details, []string{name, instStr, defStr})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate extensions: %w", err)
	}

	if count > 0 {
		result.Details = details
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: fmt.Sprintf("Found %d cryptographic extensions available. Review installation status.", count),
		})
	} else {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: "No cryptographic extensions (pgcrypto, pgsodium) found in available extensions.",
		})
	}

	return result, nil
}

// check_6_10 - SSL ciphers
type check_6_10 struct{}

func (c *check_6_10) ID() string { return "6.10" }

func (c *check_6_10) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

var allowedCiphers = map[string]bool{
	"TLS_AES_256_GCM_SHA384":        true,
	"TLS_AES_128_GCM_SHA256":        true,
	"TLS_AES_128_CCM_SHA256":        true,
	"TLS_CHACHA20_POLY1305_SHA256":  true,
	"ECDHE-RSA-AES256-GCM-SHA384":   true,
	"ECDHE-RSA-AES128-GCM-SHA256":   true,
	"ECDHE-ECDSA-AES256-GCM-SHA384": true,
	"ECDHE-ECDSA-AES128-GCM-SHA256": true,
	"DHE-RSA-AES256-GCM-SHA384":     true,
	"DHE-RSA-AES128-GCM-SHA256":     true,
}

func (c *check_6_10) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var ciphers string
	err := env.DB.QueryRow(ctx, "SHOW ssl_ciphers").Scan(&ciphers)
	if err != nil {
		return nil, fmt.Errorf("query ssl_ciphers: %w", err)
	}

	result := checker.NewResult(checker.SeverityWarning)

	var disallowed []string
	for cipher := range strings.SplitSeq(ciphers, ":") {
		cipher = strings.TrimSpace(cipher)
		if cipher == "" {
			continue
		}
		if !allowedCiphers[cipher] {
			disallowed = append(disallowed, cipher)
		}
	}

	if len(disallowed) == 0 {
		result.Pass("All configured SSL ciphers are in the allowed list.")
	} else {
		details := [][]string{{"Disallowed Cipher"}}
		for _, c := range disallowed {
			details = append(details, []string{c})
		}
		result.Details = details
		result.FailWarn(fmt.Sprintf("Found %d disallowed SSL ciphers. Only strong cipher suites should be used.", len(disallowed)))
	}

	return result, nil
}

// check_6_11 - Data anonymization
type check_6_11 struct{}

func (c *check_6_11) ID() string { return "6.11" }

func (c *check_6_11) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_6_11) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var libs string
	err := env.DB.QueryRow(ctx, "SHOW session_preload_libraries").Scan(&libs)
	if err != nil {
		return nil, fmt.Errorf("query session_preload_libraries: %w", err)
	}

	result := checker.NewResult(checker.SeverityInfo)

	libsLower := strings.ToLower(libs)
	hasAnon := strings.Contains(libsLower, "anon")
	hasPgAnonymize := strings.Contains(libsLower, "pg_anonymize")

	if hasAnon || hasPgAnonymize {
		found := "anon"
		if hasPgAnonymize {
			found = "pg_anonymize"
		}
		result.Pass(fmt.Sprintf("Data anonymization extension '%s' is configured in session_preload_libraries.", found))
	} else {
		result.Fail(fmt.Sprintf("No data anonymization extension found in session_preload_libraries ('%s'). Consider installing 'anon' or 'pg_anonymize'.", libs))
	}

	return result, nil
}
