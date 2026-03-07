package section3

import (
	"context"
	"errors"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

var (
	sqlOnly         = checker.CheckRequirements{SQLOnly: true}
	sqlOnlyCloudNA  = checker.CheckRequirements{SQLOnly: true, SkipPlatforms: checker.ManagedCloud}
	sqlOnlyLocalNA  = checker.CheckRequirements{SQLOnly: true, SkipPlatforms: checker.NonBareMetal}
)

func Checks() []checker.Check {
	checks := []checker.Check{
		&check_3_1_3{},
		&check_3_2{},
		&check_3_1_22{},
	}
	for i := range settingChecks {
		checks = append(checks, &settingChecks[i])
	}
	return checks
}

var settingChecks = []checker.SettingCheck{
	{CheckID: "3.1.2", Setting: "log_destination", Comparator: "neq", Expected: "", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.4", Setting: "log_directory", Comparator: "neq", Expected: "", Sev: checker.SeverityWarning, Reqs: sqlOnlyCloudNA},
	{CheckID: "3.1.5", Setting: "log_filename", Comparator: "neq", Expected: "", Sev: checker.SeverityInfo, Reqs: sqlOnlyCloudNA},
	{CheckID: "3.1.6", Setting: "log_file_mode", Expected: "0600", Sev: checker.SeverityWarning, Reqs: sqlOnlyCloudNA},
	{CheckID: "3.1.7", Setting: "log_truncate_on_rotation", Expected: "on", Sev: checker.SeverityWarning, Reqs: sqlOnlyLocalNA},
	{CheckID: "3.1.8", Setting: "log_rotation_age", Expected: "1d", Sev: checker.SeverityWarning, Reqs: sqlOnlyLocalNA},
	{CheckID: "3.1.9", Setting: "log_rotation_size", Comparator: "oneof", Expected: "1GB,1048576kB", Sev: checker.SeverityWarning, Reqs: sqlOnlyLocalNA},
	{CheckID: "3.1.10", Setting: "syslog_facility", Comparator: "neq", Expected: "", Sev: checker.SeverityInfo, Reqs: sqlOnly},
	{CheckID: "3.1.11", Setting: "syslog_sequence_numbers", Expected: "on", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.12", Setting: "syslog_split_messages", Expected: "on", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.13", Setting: "syslog_ident", Comparator: "neq", Expected: "", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.14", Setting: "log_min_messages", Expected: "warning", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.15", Setting: "log_min_error_statement", Expected: "error", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.16", Setting: "debug_print_parse", Expected: "off", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.17", Setting: "debug_print_rewritten", Expected: "off", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.18", Setting: "debug_print_plan", Expected: "off", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.19", Setting: "debug_pretty_print", Expected: "on", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.20", Setting: "log_connections", Expected: "on", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.21", Setting: "log_disconnections", Expected: "on", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.23", Setting: "log_statement", Comparator: "oneof", Expected: "ddl,all", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.24", Setting: "log_timezone", Comparator: "neq", Expected: "", Sev: checker.SeverityInfo, Reqs: sqlOnly},
	{CheckID: "3.1.25", Setting: "log_error_verbosity", Expected: "verbose", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.26", Setting: "log_hostname", Expected: "off", Sev: checker.SeverityWarning, Reqs: sqlOnly},
	{CheckID: "3.1.27", Setting: "log_duration", Expected: "off", Sev: checker.SeverityWarning, Reqs: sqlOnly},
}

// 3.1.3: logging_collector — on for bare-metal, off acceptable on container/zalando/rds/aurora.
type check_3_1_3 struct{}

func (c *check_3_1_3) ID() string { return "3.1.3" }

func (c *check_3_1_3) Requirements() checker.CheckRequirements { return sqlOnly }

func (c *check_3_1_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "logging_collector")
	if err != nil {
		return nil, err
	}

	result := checker.NewResult(checker.SeverityWarning)

	if val == "on" {
		result.Pass("logging_collector is enabled")
		return result, nil
	}

	// On non-bare-metal platforms, off is acceptable
	if env.Platform != checker.PlatformBareMetal {
		result.Pass("logging_collector is off (acceptable on " + env.Platform + "; logs managed by platform)")
		return result, nil
	}

	result.Fail("logging_collector is 'off', expected 'on'")
	return result, nil
}

type check_3_2 struct{}

func (c *check_3_2) ID() string { return "3.2" }

func (c *check_3_2) Requirements() checker.CheckRequirements { return sqlOnly }

func (c *check_3_2) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "shared_preload_libraries")
	if errors.Is(err, checker.ErrPermissionDenied) {
		// On RDS/Aurora, shared_preload_libraries may not be readable;
		// fall back to checking pg_extension for pgaudit.
		return c.checkViaExtension(ctx, env)
	}
	if err != nil {
		return nil, err
	}

	result := checker.NewResult(checker.SeverityWarning)

	hasPgAudit := false
	for lib := range strings.SplitSeq(val, ",") {
		if strings.TrimSpace(lib) == "pgaudit" {
			hasPgAudit = true
			break
		}
	}

	if !hasPgAudit {
		result.Fail("pgaudit is not in shared_preload_libraries (current: '" + val + "')")
		return result, nil
	}

	result.Info("pgaudit is in shared_preload_libraries")

	auditLog, err := checker.ShowSetting(ctx, env.DB, "pgaudit.log")
	if err != nil {
		result.Fail("pgaudit is loaded but pgaudit.log is not set: " + err.Error())
		return result, nil
	}

	if auditLog == "" || auditLog == "none" {
		result.Fail("pgaudit.log is set to '" + auditLog + "', should be configured for auditing")
	} else {
		result.Pass("pgaudit.log is set to: " + auditLog)
	}
	return result, nil
}

func (c *check_3_2) checkViaExtension(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var count int
	if err := env.DB.QueryRow(ctx, "SELECT COUNT(*) FROM pg_extension WHERE extname = 'pgaudit'").Scan(&count); err != nil {
		return nil, err
	}

	result := checker.NewResult(checker.SeverityWarning)
	if count == 0 {
		result.Fail("pgaudit extension is not installed (checked via pg_extension)")
		return result, nil
	}

	result.Info("pgaudit extension is installed (detected via pg_extension)")

	auditLog, err := checker.ShowSetting(ctx, env.DB, "pgaudit.log")
	if errors.Is(err, checker.ErrPermissionDenied) {
		result.Pass("pgaudit is installed; pgaudit.log not readable (managed platform)")
		return result, nil
	}
	if err != nil {
		result.Fail("pgaudit is installed but pgaudit.log is not set: " + err.Error())
		return result, nil
	}

	if auditLog == "" || auditLog == "none" {
		result.Fail("pgaudit.log is set to '" + auditLog + "', should be configured for auditing")
	} else {
		result.Pass("pgaudit.log is set to: " + auditLog)
	}
	return result, nil
}

type check_3_1_22 struct{}

func (c *check_3_1_22) ID() string { return "3.1.22" }

func (c *check_3_1_22) Requirements() checker.CheckRequirements { return sqlOnly }

func (c *check_3_1_22) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	val, err := checker.ShowSetting(ctx, env.DB, "log_line_prefix")
	if err != nil {
		return nil, err
	}

	// RDS/Aurora use their own log_line_prefix format with different tokens
	required := []string{"%m", "%p", "%d", "%u", "%a", "%h"}
	if env.IsManagedCloud() {
		required = []string{"%t", "%r", "%u", "%d", "%p"}
	}

	var missing []string
	for _, tok := range required {
		if !strings.Contains(val, tok) {
			missing = append(missing, tok)
		}
	}

	result := checker.NewResult(checker.SeverityWarning)
	if len(missing) > 0 {
		result.Fail("log_line_prefix is missing: "+strings.Join(missing, ", ")+" (current: '"+val+"')")
	} else {
		result.Pass("log_line_prefix contains all required tokens: " + val)
	}
	return result, nil
}
