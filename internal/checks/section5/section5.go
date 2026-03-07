package section5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/hba"
)

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

type check_5_1 struct{}

func (c *check_5_1) ID() string { return "5.1" }

func (c *check_5_1) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"ps"}, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_5_1) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityCritical)

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
		result.Critical("Password(s) found in process listings")
		result.Details = [][]string{{"Process"}}
		for _, f := range found {
			result.Details = append(result.Details, []string{f})
		}
	} else {
		result.Pass("No passwords found in process listings")
	}
	return result, nil
}

type check_5_2 struct{}

func (c *check_5_2) ID() string { return "5.2" }

func (c *check_5_2) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true, SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_2) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	listenAddr, err := checker.ShowSetting(ctx, env.DB, "listen_addresses")
	if err != nil {
		return nil, fmt.Errorf("query listen_addresses: %w", err)
	}

	result := checker.NewResult(checker.SeverityCritical)

	if listenAddr == "*" || listenAddr == "0.0.0.0" {
		// On container/zalando, listen_addresses='*' is expected (network policy controls access)
		if env.Platform == checker.PlatformContainer || env.Platform == checker.PlatformZalando {
			result.Pass(fmt.Sprintf("listen_addresses is '%s' (acceptable on %s; network policy controls access)", listenAddr, env.Platform))
		} else {
			result.Critical(fmt.Sprintf("listen_addresses is set to '%s', which listens on all interfaces. Restrict to specific addresses.", listenAddr))
		}
	} else {
		result.Pass(fmt.Sprintf("listen_addresses is set to '%s'.", listenAddr))
	}

	return result, nil
}

type check_5_3 struct{}

func (c *check_5_3) ID() string { return "5.3" }

func (c *check_5_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return checker.SkippedHBA(err), nil
	}

	result := checker.NewResult(checker.SeverityCritical)
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
			result.Critical(fmt.Sprintf("Line %d: local connection uses insecure auth '%s' (db=%s, user=%s)", entry.LineNumber, entry.Method, entry.Database, entry.User))
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

type check_5_4 struct{}

func (c *check_5_4) ID() string { return "5.4" }

func (c *check_5_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return checker.SkippedHBA(err), nil
	}

	result := checker.NewResult(checker.SeverityCritical)
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
			result.Critical(fmt.Sprintf("Line %d: host connection uses insecure auth '%s' (db=%s, user=%s, addr=%s)", entry.LineNumber, entry.Method, entry.Database, entry.User, entry.Address))
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

type check_5_5 struct{}

func (c *check_5_5) ID() string { return "5.5" }

func (c *check_5_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	query := "SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolconnlimit = -1"
	// On RDS/Aurora, exclude built-in managed roles
	if env.IsManagedCloud() {
		query += " AND rolname NOT IN ('rdsadmin', 'rds_replication', 'rdsrepladmin')"
	}

	rows, err := env.DB.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query connection limits: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("scan roles: %w", err)
	}

	result := checker.NewResult(checker.SeverityWarning)

	if len(names) == 0 {
		result.Pass("All login roles have connection limits configured.")
	} else {
		result.Details = [][]string{{"Role", "Connection Limit"}}
		for _, name := range names {
			result.Details = append(result.Details, []string{name, "unlimited"})
		}
		result.FailWarn(fmt.Sprintf("Found %d login roles with no connection limit set.", len(names)))
	}

	return result, nil
}

type check_5_6 struct{}

func (c *check_5_6) ID() string { return "5.6" }

func (c *check_5_6) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_6) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	libs, err := checker.ShowSetting(ctx, env.DB, "shared_preload_libraries")
	if errors.Is(err, checker.ErrPermissionDenied) {
		return checker.SkippedPermission("shared_preload_libraries"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("query shared_preload_libraries: %w", err)
	}

	result := checker.NewResult(checker.SeverityWarning)

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
		result.FailWarn(fmt.Sprintf("No password complexity module found in shared_preload_libraries ('%s'). Install 'credcheck' or 'passwordcheck'.", libs))
	}

	return result, nil
}

type check_5_7 struct{}

func (c *check_5_7) ID() string { return "5.7" }

func (c *check_5_7) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_7) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	authTimeout, err := checker.ShowSetting(ctx, env.DB, "authentication_timeout")
	if errors.Is(err, checker.ErrPermissionDenied) {
		return checker.SkippedPermission("authentication_timeout"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("query authentication_timeout: %w", err)
	}

	result := checker.NewResult(checker.SeverityWarning)

	timeoutSec, parseErr := parsePGInterval(authTimeout)
	if parseErr != nil {
		return nil, fmt.Errorf("parse authentication_timeout '%s': %w", authTimeout, parseErr)
	}

	if timeoutSec > 60 {
		result.FailWarn(fmt.Sprintf("authentication_timeout is %ds (should be <= 60s).", timeoutSec))
	} else {
		result.Info(fmt.Sprintf("authentication_timeout is %ds.", timeoutSec))
	}

	// On RDS/Aurora, auth_delay is not available as a preload library
	if env.IsManagedCloud() {
		result.Info("auth_delay check skipped (not available on " + env.Platform + ")")
		return result, nil
	}

	libs, err := checker.ShowSetting(ctx, env.DB, "shared_preload_libraries")
	if errors.Is(err, checker.ErrPermissionDenied) {
		return checker.SkippedPermission("shared_preload_libraries"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("query shared_preload_libraries: %w", err)
	}

	hasAuthDelay := strings.Contains(strings.ToLower(libs), "auth_delay")

	if !hasAuthDelay {
		result.FailWarn("auth_delay is not loaded in shared_preload_libraries.")
	} else {
		result.Info("auth_delay is loaded in shared_preload_libraries.")
	}

	return result, nil
}

type check_5_8 struct{}

func (c *check_5_8) ID() string { return "5.8" }

func (c *check_5_8) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_8) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return checker.SkippedHBA(err), nil
	}

	result := checker.NewResult(checker.SeverityCritical)

	for _, entry := range env.HBAEntries {
		if entry.Type != "host" {
			continue
		}

		addr := entry.Address
		if addr == "127.0.0.1/32" || addr == "::1/128" || addr == "localhost" || addr == "127.0.0.1" || addr == "::1" {
			continue
		}

		if entry.Method == "reject" {
			continue
		}

		result.Critical(fmt.Sprintf("Line %d: plain 'host' connection without SSL/GSSENC (db=%s, user=%s, addr=%s, method=%s)", entry.LineNumber, entry.Database, entry.User, addr, entry.Method))
	}

	if result.Status != checker.StatusFail {
		result.Pass("All non-local host connections use SSL or GSSENC")
	}
	return result, nil
}

type check_5_9 struct{}

func (c *check_5_9) ID() string { return "5.9" }

func (c *check_5_9) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_9) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return checker.SkippedHBA(err), nil
	}

	result := checker.NewResult(checker.SeverityWarning)
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

		if addr == "0.0.0.0/0" || addr == "::/0" || addr == "all" {
			hasCritical = true
			result.Critical(fmt.Sprintf("Line %d: unrestricted network range '%s' (db=%s, user=%s)", entry.LineNumber, addr, entry.Database, entry.User))
			continue
		}

		size, ok := networkSize(addr, entry.Netmask)
		if !ok {
			continue
		}

		if size > 65536 {
			hasWarning = true
			result.Warn(fmt.Sprintf("Line %d: large network range '%s' covers %d addresses (db=%s, user=%s)", entry.LineNumber, addr, size, entry.Database, entry.User))
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

type check_5_10 struct{}

func (c *check_5_10) ID() string { return "5.10" }

func (c *check_5_10) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_10) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return checker.SkippedHBA(err), nil
	}

	result := checker.NewResult(checker.SeverityWarning)

	for _, entry := range env.HBAEntries {
		if entry.Method == "reject" {
			continue
		}

		if entry.Database == "all" {
			result.FailWarn(fmt.Sprintf("Line %d: database='all' is overly broad (user=%s, type=%s, method=%s)", entry.LineNumber, entry.User, entry.Type, entry.Method))
		}
		if entry.User == "all" {
			result.FailWarn(fmt.Sprintf("Line %d: user='all' is overly broad (db=%s, type=%s, method=%s)", entry.LineNumber, entry.Database, entry.Type, entry.Method))
		}
	}

	if result.Status != checker.StatusFail {
		result.Pass("All HBA entries specify explicit databases and users")
	}
	return result, nil
}

type check_5_11 struct{}

func (c *check_5_11) ID() string { return "5.11" }

func (c *check_5_11) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Superuser: true, SkipPlatforms: checker.ManagedCloud}
}

func (c *check_5_11) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return checker.SkippedHBA(err), nil
	}

	if len(env.Superusers) == 0 {
		rows, err := env.DB.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper = true")
		if err != nil {
			return nil, err
		}
		env.Superusers, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, err
		}
	}

	superSet := make(map[string]bool)
	for _, su := range env.Superusers {
		superSet[su] = true
	}

	result := checker.NewResult(checker.SeverityCritical)

	for _, entry := range env.HBAEntries {
		if !strings.HasPrefix(entry.Type, "host") {
			continue
		}
		if entry.Method == "reject" {
			continue
		}

		user := entry.User
		if user == "all" {
			result.Critical(fmt.Sprintf("Line %d: user='all' allows superuser remote access (type=%s, addr=%s, method=%s)", entry.LineNumber, entry.Type, entry.Address, entry.Method))
		} else if superSet[user] {
			result.Critical(fmt.Sprintf("Line %d: superuser '%s' has remote access (type=%s, addr=%s, method=%s)", entry.LineNumber, user, entry.Type, entry.Address, entry.Method))
		}
	}

	if result.Status != checker.StatusFail {
		result.Pass("Superuser connections are restricted to local access only")
	}
	return result, nil
}

type check_5_12 struct{}

func (c *check_5_12) ID() string { return "5.12" }

func (c *check_5_12) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_5_12) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	passEnc, err := checker.ShowSetting(ctx, env.DB, "password_encryption")
	if err != nil {
		return nil, fmt.Errorf("query password_encryption: %w", err)
	}

	result := checker.NewResult(checker.SeverityCritical)

	if passEnc == "scram-sha-256" {
		result.Pass("password_encryption is set to 'scram-sha-256'.")
	} else {
		result.Critical(fmt.Sprintf("password_encryption is set to '%s' (should be 'scram-sha-256').", passEnc))
	}

	return result, nil
}

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

func networkSize(addr, mask string) (uint64, bool) {
	cidr := addr
	if mask != "" && !strings.Contains(addr, "/") {
		m := net.ParseIP(mask)
		if m == nil {
			return 0, false
		}
		ones, _ := net.IPMask(m.To4()).Size()
		if ones == 0 {
			ones, _ = net.IPMask(m.To16()).Size()
		}
		cidr = fmt.Sprintf("%s/%d", addr, ones)
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, false
	}

	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits <= 0 {
		return 1, true
	}
	if hostBits > 63 {
		return ^uint64(0), true
	}
	return 1 << uint(hostBits), true
}
