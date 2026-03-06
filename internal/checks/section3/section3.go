package section3

import (
	"context"
	"errors"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

func init() {
	checker.Register(&check32{})
	checker.Register(&check312{})
	checker.Register(&check313{})
	checker.Register(&check314{})
	checker.Register(&check315{})
	checker.Register(&check316{})
	checker.Register(&check317{})
	checker.Register(&check318{})
	checker.Register(&check319{})
	checker.Register(&check3110{})
	checker.Register(&check3111{})
	checker.Register(&check3112{})
	checker.Register(&check3113{})
	checker.Register(&check3114{})
	checker.Register(&check3115{})
	checker.Register(&check3116{})
	checker.Register(&check3117{})
	checker.Register(&check3118{})
	checker.Register(&check3119{})
	checker.Register(&check3120{})
	checker.Register(&check3121{})
	checker.Register(&check3122{})
	checker.Register(&check3123{})
	checker.Register(&check3124{})
	checker.Register(&check3125{})
	checker.Register(&check3126{})
	checker.Register(&check3127{})
}

// --- check 3.2 ---

type check32 struct{}

func (c *check32) ID() string { return "3.2" }

func (c *check32) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check32) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "shared_preload_libraries")
	if errors.Is(err, checker.ErrPermissionDenied) {
		return checker.SkippedPermission("shared_preload_libraries"), nil
	}
	if err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	hasPgAudit := false
	for lib := range strings.SplitSeq(val, ",") {
		if strings.TrimSpace(lib) == "pgaudit" {
			hasPgAudit = true
			break
		}
	}

	if !hasPgAudit {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "pgaudit is not in shared_preload_libraries (current: '" + val + "')",
		})
		return result, nil
	}

	result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "pgaudit is in shared_preload_libraries"})

	// Check pgaudit.log setting
	auditLog, err := checker.ShowSetting(ctx, env.DB, "pgaudit.log")
	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "pgaudit is loaded but pgaudit.log is not set: " + err.Error(),
		})
		return result, nil
	}

	if auditLog == "" || auditLog == "none" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "pgaudit.log is set to '" + auditLog + "', should be configured for auditing",
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "pgaudit.log is set to: " + auditLog})
	}
	return result, nil
}

// --- check 3.1.2 ---

type check312 struct{}

func (c *check312) ID() string { return "3.1.2" }

func (c *check312) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check312) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_destination").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val == "" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_destination is not set"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_destination is set to: " + val})
	}
	return result, nil
}

// --- check 3.1.3 ---

type check313 struct{}

func (c *check313) ID() string { return "3.1.3" }

func (c *check313) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check313) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW logging_collector").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "logging_collector is set to '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "logging_collector is enabled"})
	}
	return result, nil
}

// --- check 3.1.4 ---

type check314 struct{}

func (c *check314) ID() string { return "3.1.4" }

func (c *check314) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check314) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "log_directory")
	if errors.Is(err, checker.ErrPermissionDenied) {
		return checker.SkippedPermission("log_directory"), nil
	}
	if err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val == "" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_directory is not set"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_directory is set to: " + val})
	}
	return result, nil
}

// --- check 3.1.5 ---

type check315 struct{}

func (c *check315) ID() string { return "3.1.5" }

func (c *check315) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check315) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "log_filename")
	if errors.Is(err, checker.ErrPermissionDenied) {
		return checker.SkippedPermission("log_filename"), nil
	}
	if err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityInfo}
	if val == "" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_filename is not set"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_filename is set to: " + val})
	}
	return result, nil
}

// --- check 3.1.6 ---

type check316 struct{}

func (c *check316) ID() string { return "3.1.6" }

func (c *check316) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check316) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_file_mode").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "0600" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_file_mode is '" + val + "', expected '0600'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_file_mode is correctly set to 0600"})
	}
	return result, nil
}

// --- check 3.1.7 ---

type check317 struct{}

func (c *check317) ID() string { return "3.1.7" }

func (c *check317) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check317) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_truncate_on_rotation").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_truncate_on_rotation is '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_truncate_on_rotation is enabled"})
	}
	return result, nil
}

// --- check 3.1.8 ---

type check318 struct{}

func (c *check318) ID() string { return "3.1.8" }

func (c *check318) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check318) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_rotation_age").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "1d" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_rotation_age is '" + val + "', expected '1d'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_rotation_age is correctly set to 1d"})
	}
	return result, nil
}

// --- check 3.1.9 ---

type check319 struct{}

func (c *check319) ID() string { return "3.1.9" }

func (c *check319) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check319) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_rotation_size").Scan(&val); err != nil {
		return nil, err
	}

	// PostgreSQL reports log_rotation_size in kB; 1GB = 1048576kB.
	// SHOW returns it with a unit suffix, e.g. "1GB" or "1048576kB".
	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "1GB" && val != "1048576kB" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_rotation_size is '" + val + "', expected '1GB'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_rotation_size is correctly set to " + val})
	}
	return result, nil
}

// --- check 3.1.10 ---

type check3110 struct{}

func (c *check3110) ID() string { return "3.1.10" }

func (c *check3110) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3110) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW syslog_facility").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityInfo}
	if val == "" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "syslog_facility is not set"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "syslog_facility is set to: " + val})
	}
	return result, nil
}

// --- check 3.1.11 ---

type check3111 struct{}

func (c *check3111) ID() string { return "3.1.11" }

func (c *check3111) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3111) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW syslog_sequence_numbers").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "syslog_sequence_numbers is '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "syslog_sequence_numbers is enabled"})
	}
	return result, nil
}

// --- check 3.1.12 ---

type check3112 struct{}

func (c *check3112) ID() string { return "3.1.12" }

func (c *check3112) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3112) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW syslog_split_messages").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "syslog_split_messages is '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "syslog_split_messages is enabled"})
	}
	return result, nil
}

// --- check 3.1.13 ---

type check3113 struct{}

func (c *check3113) ID() string { return "3.1.13" }

func (c *check3113) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3113) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW syslog_ident").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val == "" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "syslog_ident is not set"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "syslog_ident is set to: " + val})
	}
	return result, nil
}

// --- check 3.1.14 ---

type check3114 struct{}

func (c *check3114) ID() string { return "3.1.14" }

func (c *check3114) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3114) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_min_messages").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "warning" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_min_messages is '" + val + "', expected 'warning'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_min_messages is correctly set to 'warning'"})
	}
	return result, nil
}

// --- check 3.1.15 ---

type check3115 struct{}

func (c *check3115) ID() string { return "3.1.15" }

func (c *check3115) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3115) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_min_error_statement").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "error" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_min_error_statement is '" + val + "', expected 'error'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_min_error_statement is correctly set to 'error'"})
	}
	return result, nil
}

// --- check 3.1.16 ---

type check3116 struct{}

func (c *check3116) ID() string { return "3.1.16" }

func (c *check3116) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3116) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW debug_print_parse").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "off" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "debug_print_parse is '" + val + "', expected 'off'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "debug_print_parse is correctly disabled"})
	}
	return result, nil
}

// --- check 3.1.17 ---

type check3117 struct{}

func (c *check3117) ID() string { return "3.1.17" }

func (c *check3117) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3117) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW debug_print_rewritten").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "off" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "debug_print_rewritten is '" + val + "', expected 'off'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "debug_print_rewritten is correctly disabled"})
	}
	return result, nil
}

// --- check 3.1.18 ---

type check3118 struct{}

func (c *check3118) ID() string { return "3.1.18" }

func (c *check3118) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3118) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW debug_print_plan").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "off" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "debug_print_plan is '" + val + "', expected 'off'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "debug_print_plan is correctly disabled"})
	}
	return result, nil
}

// --- check 3.1.19 ---

type check3119 struct{}

func (c *check3119) ID() string { return "3.1.19" }

func (c *check3119) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3119) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW debug_pretty_print").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "debug_pretty_print is '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "debug_pretty_print is enabled"})
	}
	return result, nil
}

// --- check 3.1.20 ---

type check3120 struct{}

func (c *check3120) ID() string { return "3.1.20" }

func (c *check3120) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3120) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_connections").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_connections is '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_connections is enabled"})
	}
	return result, nil
}

// --- check 3.1.21 ---

type check3121 struct{}

func (c *check3121) ID() string { return "3.1.21" }

func (c *check3121) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3121) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_disconnections").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "on" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_disconnections is '" + val + "', expected 'on'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_disconnections is enabled"})
	}
	return result, nil
}

// --- check 3.1.22 ---

type check3122 struct{}

func (c *check3122) ID() string { return "3.1.22" }

func (c *check3122) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3122) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_line_prefix").Scan(&val); err != nil {
		return nil, err
	}

	required := []string{"%m", "%p", "%d", "%u", "%a", "%h"}
	var missing []string
	for _, tok := range required {
		if !strings.Contains(val, tok) {
			missing = append(missing, tok)
		}
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if len(missing) > 0 {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "log_line_prefix is missing: " + strings.Join(missing, ", ") + " (current: '" + val + "')",
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_line_prefix contains all required tokens: " + val})
	}
	return result, nil
}

// --- check 3.1.23 ---

type check3123 struct{}

func (c *check3123) ID() string { return "3.1.23" }

func (c *check3123) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3123) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_statement").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val == "ddl" || val == "all" {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_statement is set to '" + val + "'"})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_statement is '" + val + "', expected 'ddl' or 'all'"})
	}
	return result, nil
}

// --- check 3.1.24 ---

type check3124 struct{}

func (c *check3124) ID() string { return "3.1.24" }

func (c *check3124) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3124) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_timezone").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityInfo}
	if val == "" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_timezone is not set"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_timezone is set to: " + val})
	}
	return result, nil
}

// --- check 3.1.25 ---

type check3125 struct{}

func (c *check3125) ID() string { return "3.1.25" }

func (c *check3125) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3125) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_error_verbosity").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "verbose" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_error_verbosity is '" + val + "', expected 'verbose'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_error_verbosity is correctly set to 'verbose'"})
	}
	return result, nil
}

// --- check 3.1.26 ---

type check3126 struct{}

func (c *check3126) ID() string { return "3.1.26" }

func (c *check3126) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3126) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_hostname").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "off" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_hostname is '" + val + "', expected 'off'"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_hostname is correctly disabled"})
	}
	return result, nil
}

// --- check 3.1.27 ---

type check3127 struct{}

func (c *check3127) ID() string { return "3.1.27" }

func (c *check3127) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check3127) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SHOW log_duration").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val != "off" {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: "log_duration is '" + val + "', expected 'off' (use log_min_duration_statement instead)"})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{Level: "SUCCESS", Content: "log_duration is correctly disabled"})
	}
	return result, nil
}
