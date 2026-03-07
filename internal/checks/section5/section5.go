package section5

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/hba"
	"github.com/pgharden/pgharden/internal/netmask"
)

// Checks returns all Section 5 checks.
func Checks() []checker.Check {
	return []checker.Check{
		&check_5_1{},
		&check_5_2{},
		&check_5_3{},
		&check_5_4{},
		&check_5_5{},
		&check_5_6{},
		&check_5_7{},
		&check_5_8{},
		&check_5_9{},
		&check_5_10{},
		&check_5_11{},
		&check_5_12{},
	}
}

// ensureHBA loads the HBA entries into env if not already loaded.
func ensureHBA(ctx context.Context, env *checker.Environment) error {
	if env.HBALoaded {
		return nil
	}
	if env.PGVersion >= 15 {
		entries, err := hba.LoadFromSQL(ctx, env.DB)
		if err == nil {
			env.HBAEntries = entries
			env.HBALoaded = true
			return nil
		}
	}
	if env.HasFilesystem {
		var hbaFile string
		if err := env.DB.QueryRow(ctx, "SHOW hba_file").Scan(&hbaFile); err == nil && hbaFile != "" {
			entries, err := hba.LoadFromFile(hbaFile)
			if err == nil {
				env.HBAEntries = entries
				env.HBALoaded = true
				return nil
			}
		}
	}
	return fmt.Errorf("cannot load pg_hba.conf")
}

// ---------------------------------------------------------------------------
// Check 5.1
// ---------------------------------------------------------------------------

type check_5_1 struct{}

func (c *check_5_1) ID() string { return "5.1" }

func (c *check_5_1) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"ps"}}
}

func (c *check_5_1) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	out, err := exec.CommandContext(ctx, "ps", "-ef").CombinedOutput()
	if err != nil {
		result.Status = checker.StatusSkipped
		result.SkipReason = "Cannot run ps: " + err.Error()
		return result, nil
	}

	var found []string
	for line := range strings.SplitSeq(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "pgpassword") || strings.Contains(lower, "password=") {
			found = append(found, strings.TrimSpace(line))
		}
	}

	if len(found) > 0 {
		result.Fail("CRITICAL", "Password(s) found in process listings")
		result.Details = [][]string{{"Process"}}
		for _, f := range found {
			result.Details = append(result.Details, []string{f})
		}
	} else {
		result.Pass("No passwords found in process listings")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.2
// ---------------------------------------------------------------------------

type check_5_2 struct{}

func (c *check_5_2) ID() string { return "5.2" }

func (c *check_5_2) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_2) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var listenAddr string
	err := env.DB.QueryRow(ctx, "SHOW listen_addresses").Scan(&listenAddr)
	if err != nil {
		return nil, fmt.Errorf("query listen_addresses: %w", err)
	}

	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	if listenAddr == "*" || listenAddr == "0.0.0.0" {
		result.Fail("CRITICAL", fmt.Sprintf("listen_addresses is set to '%s', which listens on all interfaces. Restrict to specific addresses.", listenAddr))
	} else {
		result.Pass(fmt.Sprintf("listen_addresses is set to '%s'.", listenAddr))
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.3
// ---------------------------------------------------------------------------

type check_5_3 struct{}

func (c *check_5_3) ID() string { return "5.3" }

func (c *check_5_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check_5_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return &checker.CheckResult{
			Status:     checker.StatusSkipped,
			Severity:   checker.SeverityCritical,
			SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
		}, nil
	}

	result := &checker.CheckResult{Severity: checker.SeverityCritical}
	hasFail := false
	hasWarn := false

	for _, entry := range env.HBAEntries {
		if entry.Type != "local" {
			continue
		}

		sec := hba.ClassifyAuthMethod(entry.Method)
		switch sec {
		case hba.AuthForbidden:
			hasFail = true
			result.Messages = append(result.Messages, checker.Message{
				Level:   "CRITICAL",
				Content: fmt.Sprintf("Line %d: local connection uses insecure auth '%s' (db=%s, user=%s)", entry.LineNumber, entry.Method, entry.Database, entry.User),
			})
		case hba.AuthWeak:
			hasWarn = true
			result.Warn(fmt.Sprintf("Line %d: local connection uses weak auth '%s' (db=%s, user=%s)", entry.LineNumber, entry.Method, entry.Database, entry.User))
		}
	}

	if hasFail {
		result.Status = checker.StatusFail
		result.Severity = checker.SeverityCritical
	} else if hasWarn {
		result.Status = checker.StatusFail
		result.Severity = checker.SeverityWarning
	} else {
		result.Pass("All local connections use secure authentication")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.4
// ---------------------------------------------------------------------------

type check_5_4 struct{}

func (c *check_5_4) ID() string { return "5.4" }

func (c *check_5_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check_5_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return &checker.CheckResult{
			Status:     checker.StatusSkipped,
			Severity:   checker.SeverityCritical,
			SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
		}, nil
	}

	result := &checker.CheckResult{Severity: checker.SeverityCritical}
	hasFail := false
	hasWarn := false

	for _, entry := range env.HBAEntries {
		if !strings.HasPrefix(entry.Type, "host") {
			continue
		}

		sec := hba.ClassifyAuthMethod(entry.Method)
		switch sec {
		case hba.AuthForbidden:
			hasFail = true
			result.Messages = append(result.Messages, checker.Message{
				Level:   "CRITICAL",
				Content: fmt.Sprintf("Line %d: host connection uses insecure auth '%s' (db=%s, user=%s, addr=%s)", entry.LineNumber, entry.Method, entry.Database, entry.User, entry.Address),
			})
		case hba.AuthWeak:
			hasWarn = true
			result.Warn(fmt.Sprintf("Line %d: host connection uses weak auth '%s' (db=%s, user=%s, addr=%s)", entry.LineNumber, entry.Method, entry.Database, entry.User, entry.Address))
		}
	}

	if hasFail {
		result.Status = checker.StatusFail
		result.Severity = checker.SeverityCritical
	} else if hasWarn {
		result.Status = checker.StatusFail
		result.Severity = checker.SeverityWarning
	} else {
		result.Pass("All host connections use secure authentication")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.5
// ---------------------------------------------------------------------------

type check_5_5 struct{}

func (c *check_5_5) ID() string { return "5.5" }

func (c *check_5_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT rolname, rolconnlimit FROM pg_roles WHERE rolcanlogin AND rolconnlimit = -1")
	if err != nil {
		return nil, fmt.Errorf("query connection limits: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	details := [][]string{{"Role", "Connection Limit"}}
	count := 0
	for rows.Next() {
		var name string
		var connLimit int
		if err := rows.Scan(&name, &connLimit); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		details = append(details, []string{name, "unlimited"})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}

	if count == 0 {
		result.Pass("All login roles have connection limits configured.")
	} else {
		result.Details = details
		result.Fail("WARNING", fmt.Sprintf("Found %d login roles with no connection limit set.", count))
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.6
// ---------------------------------------------------------------------------

type check_5_6 struct{}

func (c *check_5_6) ID() string { return "5.6" }

func (c *check_5_6) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_6) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var libs string
	err := env.DB.QueryRow(ctx, "SHOW shared_preload_libraries").Scan(&libs)
	if err != nil {
		return nil, fmt.Errorf("query shared_preload_libraries: %w", err)
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	libsLower := strings.ToLower(libs)
	hasCredcheck := strings.Contains(libsLower, "credcheck")
	hasPasswordcheck := strings.Contains(libsLower, "passwordcheck")

	if hasCredcheck || hasPasswordcheck {
		found := "credcheck"
		if hasPasswordcheck {
			found = "passwordcheck"
		}
		result.Pass(fmt.Sprintf("Password complexity module '%s' is loaded in shared_preload_libraries.", found))
	} else {
		result.Fail("WARNING", fmt.Sprintf("No password complexity module found in shared_preload_libraries ('%s'). Install 'credcheck' or 'passwordcheck'.", libs))
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.7
// ---------------------------------------------------------------------------

type check_5_7 struct{}

func (c *check_5_7) ID() string { return "5.7" }

func (c *check_5_7) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_7) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var authTimeout string
	err := env.DB.QueryRow(ctx, "SHOW authentication_timeout").Scan(&authTimeout)
	if err != nil {
		return nil, fmt.Errorf("query authentication_timeout: %w", err)
	}

	var libs string
	err = env.DB.QueryRow(ctx, "SHOW shared_preload_libraries").Scan(&libs)
	if err != nil {
		return nil, fmt.Errorf("query shared_preload_libraries: %w", err)
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	// Parse timeout value — SHOW returns values like "1min", "30s", or "60".
	timeoutSec, parseErr := parsePGInterval(authTimeout)
	if parseErr != nil {
		return nil, fmt.Errorf("parse authentication_timeout '%s': %w", authTimeout, parseErr)
	}

	hasAuthDelay := strings.Contains(strings.ToLower(libs), "auth_delay")
	failed := false

	if timeoutSec > 60 {
		failed = true
		result.Warn(fmt.Sprintf("authentication_timeout is %ds (should be <= 60s).", timeoutSec))
	} else {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: fmt.Sprintf("authentication_timeout is %ds.", timeoutSec),
		})
	}

	if !hasAuthDelay {
		failed = true
		result.Warn("auth_delay is not loaded in shared_preload_libraries.")
	} else {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "auth_delay is loaded in shared_preload_libraries.",
		})
	}

	if failed {
		result.Status = checker.StatusFail
	} else {
		result.Status = checker.StatusPass
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.8
// ---------------------------------------------------------------------------

type check_5_8 struct{}

func (c *check_5_8) ID() string { return "5.8" }

func (c *check_5_8) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check_5_8) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return &checker.CheckResult{
			Status:     checker.StatusSkipped,
			Severity:   checker.SeverityCritical,
			SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
		}, nil
	}

	result := &checker.CheckResult{Severity: checker.SeverityCritical}
	hasFail := false

	for _, entry := range env.HBAEntries {
		// Only flag plain "host" entries (not hostssl, hostgssenc)
		if entry.Type != "host" {
			continue
		}

		// Skip localhost connections
		addr := entry.Address
		if addr == "127.0.0.1/32" || addr == "::1/128" || addr == "localhost" || addr == "127.0.0.1" || addr == "::1" {
			continue
		}

		// Skip reject method
		if entry.Method == "reject" {
			continue
		}

		hasFail = true
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: fmt.Sprintf("Line %d: plain 'host' connection without SSL/GSSENC (db=%s, user=%s, addr=%s, method=%s)", entry.LineNumber, entry.Database, entry.User, addr, entry.Method),
		})
	}

	if hasFail {
		result.Status = checker.StatusFail
	} else {
		result.Pass("All non-local host connections use SSL or GSSENC")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.9
// ---------------------------------------------------------------------------

type check_5_9 struct{}

func (c *check_5_9) ID() string { return "5.9" }

func (c *check_5_9) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check_5_9) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return &checker.CheckResult{
			Status:     checker.StatusSkipped,
			Severity:   checker.SeverityCritical,
			SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
		}, nil
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	hasCritical := false
	hasWarning := false

	for _, entry := range env.HBAEntries {
		if !strings.HasPrefix(entry.Type, "host") {
			continue
		}
		if entry.Method == "reject" {
			continue
		}

		addr := entry.Address
		if addr == "" {
			continue
		}

		// Build CIDR string
		cidr := addr
		if entry.Netmask != "" && !strings.Contains(cidr, "/") {
			cidr = addr + " " + entry.Netmask
		}

		// Check for all-addresses patterns
		if addr == "0.0.0.0/0" || addr == "::/0" || addr == "all" {
			hasCritical = true
			result.Messages = append(result.Messages, checker.Message{
				Level:   "CRITICAL",
				Content: fmt.Sprintf("Line %d: unrestricted network range '%s' (db=%s, user=%s)", entry.LineNumber, addr, entry.Database, entry.User),
			})
			continue
		}

		size, err := netmask.NetworkSize(cidr)
		if err != nil {
			continue
		}

		if size > 65536 {
			hasWarning = true
			result.Warn(fmt.Sprintf("Line %d: large CIDR range '%s' covers %d addresses (db=%s, user=%s)", entry.LineNumber, cidr, size, entry.Database, entry.User))
		}
	}

	if hasCritical {
		result.Status = checker.StatusFail
		result.Severity = checker.SeverityCritical
	} else if hasWarning {
		result.Status = checker.StatusFail
		result.Severity = checker.SeverityWarning
	} else {
		result.Pass("All CIDR ranges are appropriately scoped")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.10
// ---------------------------------------------------------------------------

type check_5_10 struct{}

func (c *check_5_10) ID() string { return "5.10" }

func (c *check_5_10) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check_5_10) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return &checker.CheckResult{
			Status:     checker.StatusSkipped,
			Severity:   checker.SeverityWarning,
			SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
		}, nil
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	hasWarning := false

	for _, entry := range env.HBAEntries {
		// Skip reject rules -- they're fine with 'all'
		if entry.Method == "reject" {
			continue
		}

		if entry.Database == "all" {
			hasWarning = true
			result.Warn(fmt.Sprintf("Line %d: database='all' is overly broad (user=%s, type=%s, method=%s)", entry.LineNumber, entry.User, entry.Type, entry.Method))
		}
		if entry.User == "all" {
			hasWarning = true
			result.Warn(fmt.Sprintf("Line %d: user='all' is overly broad (db=%s, type=%s, method=%s)", entry.LineNumber, entry.Database, entry.Type, entry.Method))
		}
	}

	if hasWarning {
		result.Status = checker.StatusFail
	} else {
		result.Pass("All HBA entries specify explicit databases and users")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.11
// ---------------------------------------------------------------------------

type check_5_11 struct{}

func (c *check_5_11) ID() string { return "5.11" }

func (c *check_5_11) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Superuser: true}
}

func (c *check_5_11) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return &checker.CheckResult{
			Status:     checker.StatusSkipped,
			Severity:   checker.SeverityCritical,
			SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
		}, nil
	}

	// Load superuser list if not cached
	if len(env.Superusers) == 0 {
		rows, err := env.DB.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper = true")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return nil, err
			}
			env.Superusers = append(env.Superusers, name)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	superSet := make(map[string]bool)
	for _, su := range env.Superusers {
		superSet[su] = true
	}

	result := &checker.CheckResult{Severity: checker.SeverityCritical}
	hasFail := false

	for _, entry := range env.HBAEntries {
		// Only check remote connection types
		if !strings.HasPrefix(entry.Type, "host") {
			continue
		}
		if entry.Method == "reject" {
			continue
		}

		// Check if this entry allows a superuser
		user := entry.User
		if user == "all" {
			// 'all' includes superusers
			hasFail = true
			result.Messages = append(result.Messages, checker.Message{
				Level:   "CRITICAL",
				Content: fmt.Sprintf("Line %d: user='all' allows superuser remote access (type=%s, addr=%s, method=%s)", entry.LineNumber, entry.Type, entry.Address, entry.Method),
			})
		} else if superSet[user] {
			hasFail = true
			result.Messages = append(result.Messages, checker.Message{
				Level:   "CRITICAL",
				Content: fmt.Sprintf("Line %d: superuser '%s' has remote access (type=%s, addr=%s, method=%s)", entry.LineNumber, user, entry.Type, entry.Address, entry.Method),
			})
		}
	}

	if hasFail {
		result.Status = checker.StatusFail
	} else {
		result.Pass("Superuser connections are restricted to local access only")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 5.12
// ---------------------------------------------------------------------------

type check_5_12 struct{}

func (c *check_5_12) ID() string { return "5.12" }

func (c *check_5_12) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_12) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var passEnc string
	err := env.DB.QueryRow(ctx, "SHOW password_encryption").Scan(&passEnc)
	if err != nil {
		return nil, fmt.Errorf("query password_encryption: %w", err)
	}

	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	if passEnc == "scram-sha-256" {
		result.Pass("password_encryption is set to 'scram-sha-256'.")
	} else {
		result.Fail("CRITICAL", fmt.Sprintf("password_encryption is set to '%s' (should be 'scram-sha-256').", passEnc))
	}

	return result, nil
}

// parsePGInterval parses a PostgreSQL time value (e.g., "1min", "30s", "60") into seconds.
func parsePGInterval(val string) (int, error) {
	val = strings.TrimSpace(val)
	for _, suffix := range []struct {
		s string
		m int
	}{
		{"min", 60},
		{"ms", 0},
		{"s", 1},
		{"h", 3600},
		{"d", 86400},
	} {
		if strings.HasSuffix(val, suffix.s) {
			n, err := strconv.Atoi(strings.TrimSuffix(val, suffix.s))
			if err != nil {
				return 0, err
			}
			return n * suffix.m, nil
		}
	}
	return strconv.Atoi(val)
}
