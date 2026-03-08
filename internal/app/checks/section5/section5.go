package section5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pscheid92/pgharden/internal/domain"
	"github.com/pscheid92/pgharden/internal/app/hba"
)

func Checks() []domain.Check {
	return []domain.Check{
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
		&check_5_13{},
	}
}

func ensureHBA(ctx context.Context, env *domain.Environment) error {
	if env.HBALoaded {
		return env.HBAError
	}
	env.HBALoaded = true
	// Only attempt pg_hba_file_rules if user has privileges (superuser or pg_read_all_settings).
	// Without this guard, the query generates ERROR entries in the postgres log.
	if env.PGVersion >= 15 && (env.IsSuperuser || env.IsRDSSuperuser) {
		entries, err := hba.LoadFromSQL(ctx, env.DB)
		if err == nil {
			env.HBAEntries = entries
			return nil
		}
	}
	if env.HasFilesystem {
		var hbaFile string
		if err := env.DB.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name = 'hba_file'").Scan(&hbaFile); err == nil && hbaFile != "" {
			entries, err := hba.LoadFromFile(env.GetFS(), hbaFile)
			if err == nil {
				env.HBAEntries = entries
				return nil
			}
		}
	}
	env.HBAError = fmt.Errorf("cannot load pg_hba.conf")
	return env.HBAError
}

type check_5_1 struct{}

func (c *check_5_1) ID() string        { return "5.1" }
func (c *check_5_1) Reference() *domain.Reference { return domain.CISRef("5.1") }

func (c *check_5_1) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Commands: []string{"ps"}, SkipPlatforms: domain.NonBareMetal}
}

func (c *check_5_1) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityCritical)

	out, err := env.GetCmd().Run(ctx, "ps", "-ef")
	if err != nil {
		result.Status = domain.StatusSkipped
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

func (c *check_5_2) ID() string        { return "5.2" }
func (c *check_5_2) Reference() *domain.Reference { return domain.CISRef("5.2") }

func (c *check_5_2) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true, SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_2) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	listenAddr, err := domain.ShowSetting(ctx, env.DB, "listen_addresses")
	if err != nil {
		return nil, fmt.Errorf("query listen_addresses: %w", err)
	}

	result := domain.NewResult(domain.SeverityCritical)

	if listenAddr == "*" || listenAddr == "0.0.0.0" {
		// On container/kubernetes, listen_addresses='*' is expected (network policy controls access)
		if env.Platform == domain.PlatformContainer || env.Platform == domain.PlatformKubernetes {
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

func (c *check_5_3) ID() string        { return "5.3" }
func (c *check_5_3) Reference() *domain.Reference { return domain.CISRef("5.3") }

func (c *check_5_3) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_3) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
	}

	result := domain.NewResult(domain.SeverityCritical)
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
		result.Status = domain.StatusFail
		result.Severity = domain.SeverityCritical
	} else if hasWarn {
		result.Status = domain.StatusFail
		result.Severity = domain.SeverityWarning
	} else {
		result.Pass("All local connections use secure authentication")
	}
	return result, nil
}

type check_5_4 struct{}

func (c *check_5_4) ID() string        { return "5.4" }
func (c *check_5_4) Reference() *domain.Reference { return domain.CISRef("5.4") }

func (c *check_5_4) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_4) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
	}

	result := domain.NewResult(domain.SeverityCritical)
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
		result.Status = domain.StatusFail
		result.Severity = domain.SeverityCritical
	} else if hasWarn {
		result.Status = domain.StatusFail
		result.Severity = domain.SeverityWarning
	} else {
		result.Pass("All host connections use secure authentication")
	}
	return result, nil
}

type check_5_5 struct{}

func (c *check_5_5) ID() string        { return "5.5" }
func (c *check_5_5) Reference() *domain.Reference { return domain.CISRef("5.5") }

func (c *check_5_5) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_5_5) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
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

	result := domain.NewResult(domain.SeverityWarning)

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

func (c *check_5_6) ID() string        { return "5.6" }
func (c *check_5_6) Reference() *domain.Reference { return domain.CISRef("5.6") }

func (c *check_5_6) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_5_6) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	libs, err := domain.ShowSetting(ctx, env.DB, "shared_preload_libraries")
	if errors.Is(err, domain.ErrPermissionDenied) {
		return domain.SkippedPermission("shared_preload_libraries"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("query shared_preload_libraries: %w", err)
	}

	result := domain.NewResult(domain.SeverityWarning)

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

func (c *check_5_7) ID() string        { return "5.7" }
func (c *check_5_7) Reference() *domain.Reference { return domain.CISRef("5.7") }

func (c *check_5_7) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_5_7) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	authTimeout, err := domain.ShowSetting(ctx, env.DB, "authentication_timeout")
	if errors.Is(err, domain.ErrPermissionDenied) {
		return domain.SkippedPermission("authentication_timeout"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("query authentication_timeout: %w", err)
	}

	result := domain.NewResult(domain.SeverityWarning)

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

	libs, err := domain.ShowSetting(ctx, env.DB, "shared_preload_libraries")
	if errors.Is(err, domain.ErrPermissionDenied) {
		return domain.SkippedPermission("shared_preload_libraries"), nil
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

func (c *check_5_8) ID() string        { return "5.8" }
func (c *check_5_8) Reference() *domain.Reference { return domain.CISRef("5.8") }

func (c *check_5_8) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_8) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
	}

	result := domain.NewResult(domain.SeverityCritical)

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

	if result.Status != domain.StatusFail {
		result.Pass("All non-local host connections use SSL or GSSENC")
	}
	return result, nil
}

type check_5_9 struct{}

func (c *check_5_9) ID() string        { return "5.9" }
func (c *check_5_9) Reference() *domain.Reference { return domain.CISRef("5.9") }

func (c *check_5_9) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_9) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
	}

	result := domain.NewResult(domain.SeverityWarning)
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
		result.Status = domain.StatusFail
		result.Severity = domain.SeverityCritical
	} else if hasWarning {
		result.Status = domain.StatusFail
		result.Severity = domain.SeverityWarning
	} else {
		result.Pass("All CIDR ranges are appropriately scoped")
	}
	return result, nil
}

type check_5_10 struct{}

func (c *check_5_10) ID() string        { return "5.10" }
func (c *check_5_10) Reference() *domain.Reference { return domain.CISRef("5.10") }

func (c *check_5_10) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_10) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
	}

	result := domain.NewResult(domain.SeverityWarning)

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

	if result.Status != domain.StatusFail {
		result.Pass("All HBA entries specify explicit databases and users")
	}
	return result, nil
}

type check_5_11 struct{}

func (c *check_5_11) ID() string        { return "5.11" }
func (c *check_5_11) Reference() *domain.Reference { return domain.CISRef("5.11") }

func (c *check_5_11) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Superuser: true, SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_11) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
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

	result := domain.NewResult(domain.SeverityCritical)

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

	if result.Status != domain.StatusFail {
		result.Pass("Superuser connections are restricted to local access only")
	}
	return result, nil
}

type check_5_12 struct{}

func (c *check_5_12) ID() string        { return "5.12" }
func (c *check_5_12) Reference() *domain.Reference { return domain.CISRef("5.12") }

func (c *check_5_12) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_5_12) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	passEnc, err := domain.ShowSetting(ctx, env.DB, "password_encryption")
	if err != nil {
		return nil, fmt.Errorf("query password_encryption: %w", err)
	}

	result := domain.NewResult(domain.SeverityCritical)

	if passEnc == "scram-sha-256" {
		result.Pass("password_encryption is set to 'scram-sha-256'.")
	} else {
		result.Critical(fmt.Sprintf("password_encryption is set to '%s' (should be 'scram-sha-256').", passEnc))
	}

	return result, nil
}

type check_5_13 struct{}

func (c *check_5_13) ID() string        { return "5.13" }
func (c *check_5_13) Reference() *domain.Reference { return domain.CISRef("5.13") }

func (c *check_5_13) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_5_13) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	if err := ensureHBA(ctx, env); err != nil {
		return domain.SkippedHBA(err), nil
	}

	result := domain.NewResult(domain.SeverityWarning)

	// For each pair of entries, check if a broad permissive rule shadows a later restrictive one.
	for i, broad := range env.HBAEntries {
		if broad.Method == "reject" {
			continue
		}

		for j := i + 1; j < len(env.HBAEntries); j++ {
			narrow := env.HBAEntries[j]

			// Only flag if the later rule is more restrictive (reject, or narrower scope)
			if !hbaCouldShadow(broad, narrow) {
				continue
			}

			result.FailWarn(fmt.Sprintf(
				"Line %d (%s db=%s user=%s addr=%s method=%s) shadows line %d (%s db=%s user=%s addr=%s method=%s)",
				broad.LineNumber, broad.Type, broad.Database, broad.User, broad.Address, broad.Method,
				narrow.LineNumber, narrow.Type, narrow.Database, narrow.User, narrow.Address, narrow.Method,
			))
		}
	}

	if result.Status != domain.StatusFail {
		result.Pass("No permissive HBA rules shadow later restrictive rules")
	}
	return result, nil
}

// hbaCouldShadow returns true if 'broad' could shadow 'narrow' because broad
// matches a superset of connections and is more permissive.
func hbaCouldShadow(broad, narrow domain.HBAEntry) bool {
	// Type must be compatible (both local, or both host-family)
	if broad.Type == "local" && narrow.Type != "local" {
		return false
	}
	if broad.Type != "local" && narrow.Type == "local" {
		return false
	}

	// The broad rule must match at least everything the narrow rule matches.
	if !fieldCovers(broad.Database, narrow.Database) {
		return false
	}
	if !fieldCovers(broad.User, narrow.User) {
		return false
	}

	// For host entries, check address coverage.
	if broad.Type != "local" {
		if !addressCovers(broad.Address, narrow.Address) {
			return false
		}
	}

	// The broad rule must be more permissive than the narrow rule.
	// Flag when: broad allows access (not reject) and narrow denies/restricts it.
	if narrow.Method == "reject" {
		return true
	}

	return false
}

// fieldCovers returns true if 'broad' covers 'narrow' (e.g., "all" covers anything).
func fieldCovers(broad, narrow string) bool {
	if broad == "all" {
		return true
	}
	return broad == narrow
}

// addressCovers returns true if the broad address range includes the narrow range.
func addressCovers(broad, narrow string) bool {
	if broad == "all" || broad == "0.0.0.0/0" || broad == "::/0" {
		return true
	}
	if broad == narrow {
		return true
	}

	broadPrefix, err1 := netip.ParsePrefix(broad)
	narrowPrefix, err2 := netip.ParsePrefix(narrow)
	if err1 != nil || err2 != nil {
		return broad == narrow
	}

	// broad covers narrow if broad contains narrow's first address and broad's prefix is shorter.
	return broadPrefix.Contains(narrowPrefix.Addr()) && broadPrefix.Bits() <= narrowPrefix.Bits()
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
