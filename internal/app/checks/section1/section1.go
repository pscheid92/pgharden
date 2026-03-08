package section1

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/pscheid92/pgharden/internal/domain"
)

var errNoAccess = errors.New("requires filesystem access or pg_read_server_files role")

// readPGVersion tries to read the PG_VERSION file content via SQL first
// (pg_read_file), then falls back to filesystem. Returns errNoAccess if
// neither method is available.
func readPGVersion(ctx context.Context, env *domain.Environment) (string, error) {
	var content string
	if err := env.DB.QueryRow(ctx, "SELECT pg_read_file('PG_VERSION')").Scan(&content); err == nil {
		return strings.TrimSpace(content), nil
	}

	if env.HasFilesystem {
		data, err := fs.ReadFile(env.GetFS(), domain.FSPath(filepath.Join(env.DataDir, "PG_VERSION")))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}

	return "", errNoAccess
}

func Checks() []domain.Check {
	return []domain.Check{
		&check_1_1{},
		&check_1_2{},
		&check_1_3{},
		&check_1_5{},
		&check_1_6{},
		&check_1_7{},
		&check_1_8{},
		&check_1_9{},
		&check_1_1_1{},
		&check_1_4_1{},
		&check_1_4_2{},
		&check_1_4_3{},
		&check_1_4_4{},
		&check_1_4_5{},
	}
}

type check_1_1 struct{}

func (c *check_1_1) ID() string          { return "1.1" }
func (c *check_1_1) Reference() *domain.Reference { return domain.CISRef("1.1") }

func (c *check_1_1) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_1) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	return domain.ManualResult("Manually verify that PostgreSQL packages are obtained from authorized repositories"), nil
}

type check_1_2 struct{}

func (c *check_1_2) ID() string          { return "1.2" }
func (c *check_1_2) Reference() *domain.Reference { return domain.CISRef("1.2") }

func (c *check_1_2) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Commands: []string{"systemctl"}, SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_2) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	out, err := env.GetCmd().Run(ctx, "systemctl", "is-enabled", "postgresql")
	output := strings.TrimSpace(string(out))

	if err != nil {
		out2, err2 := env.GetCmd().Run(ctx, "bash", "-c", "systemctl is-enabled postgresql*")
		output2 := strings.TrimSpace(string(out2))
		if err2 != nil || !strings.Contains(output2, "enabled") {
			result.Fail("PostgreSQL systemd service is not enabled: " + output)
			return result, nil
		}
		output = output2
	}

	if strings.Contains(output, "enabled") {
		result.Pass("PostgreSQL systemd service is enabled")
	} else {
		result.Fail("PostgreSQL systemd service is not enabled: " + output)
	}
	return result, nil
}

type check_1_3 struct{}

func (c *check_1_3) ID() string          { return "1.3" }
func (c *check_1_3) Reference() *domain.Reference { return domain.CISRef("1.3") }

func (c *check_1_3) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_3) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	_, err := readPGVersion(ctx, env)
	if errors.Is(err, errNoAccess) {
		result.Status = domain.StatusSkipped
		result.SkipReason = errNoAccess.Error()
		return result, nil
	}
	if err != nil {
		result.Fail("PG_VERSION file not found in PGDATA: " + err.Error())
		return result, nil
	}

	result.Pass("Data cluster is initialized (PG_VERSION exists in " + env.DataDir + ")")
	return result, nil
}

type check_1_5 struct{}

func (c *check_1_5) ID() string          { return "1.5" }
func (c *check_1_5) Reference() *domain.Reference { return domain.CISRef("1.5") }

func (c *check_1_5) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{}
}

func (c *check_1_5) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	return domain.ManualResult("Manually verify PostgreSQL is at the latest available version. Running: " + env.PGVersionFull), nil
}

type check_1_6 struct{}

func (c *check_1_6) ID() string          { return "1.6" }
func (c *check_1_6) Reference() *domain.Reference { return domain.CISRef("1.6") }

func (c *check_1_6) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Filesystem: true, SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_6) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityCritical)

	profileFiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/environment",
	}

	homeGuesses := []string{"/var/lib/postgresql", "/var/lib/pgsql", "/home/postgres"}
	for _, home := range homeGuesses {
		profileFiles = append(profileFiles,
			home+"/.bashrc",
			home+"/.bash_profile",
			home+"/.profile",
		)
	}

	fsys := env.GetFS()
	var found []string
	for _, pf := range profileFiles {
		data, err := fs.ReadFile(fsys, domain.FSPath(pf))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "PGPASSWORD") {
			found = append(found, pf)
		}
	}

	if len(found) > 0 {
		result.Critical("PGPASSWORD found in shell profile(s): " + strings.Join(found, ", "))
	} else {
		result.Pass("PGPASSWORD not found in any checked shell profile")
	}
	return result, nil
}

type check_1_7 struct{}

func (c *check_1_7) ID() string          { return "1.7" }
func (c *check_1_7) Reference() *domain.Reference { return domain.CISRef("1.7") }

func (c *check_1_7) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Filesystem: true, SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_7) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityCritical)

	if env.OS != "linux" {
		result.Status = domain.StatusSkipped
		result.SkipReason = "Process environment check only available on Linux"
		return result, nil
	}

	fsys := env.GetFS()
	matches, err := fs.Glob(fsys, "proc/[0-9]*/environ")
	if err != nil {
		result.Status = domain.StatusSkipped
		result.SkipReason = "Cannot enumerate /proc entries: " + err.Error()
		return result, nil
	}

	var pidsWithPassword []string
	for _, envFile := range matches {
		data, err := fs.ReadFile(fsys, envFile)
		if err != nil {
			continue // permission denied is expected for other users' processes
		}
		if strings.Contains(string(data), "PGPASSWORD") {
			// envFile is "proc/<pid>/environ"
			parts := strings.Split(envFile, "/")
			if len(parts) >= 2 {
				pidsWithPassword = append(pidsWithPassword, parts[1])
			}
		}
	}

	if len(pidsWithPassword) > 0 {
		result.Critical(fmt.Sprintf("PGPASSWORD found in environment of %d process(es): PIDs %s", len(pidsWithPassword), strings.Join(pidsWithPassword, ", ")))
	} else {
		result.Pass("PGPASSWORD not found in any process environment")
	}
	return result, nil
}

type check_1_8 struct{}

func (c *check_1_8) ID() string          { return "1.8" }
func (c *check_1_8) Reference() *domain.Reference { return domain.CISRef("1.8") }

func (c *check_1_8) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_1_8) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT e.extname, e.extversion, n.nspname
		FROM pg_extension e
		JOIN pg_namespace n ON e.extnamespace = n.oid
		ORDER BY e.extname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &domain.CheckResult{
		Status:   domain.StatusManual,
		Severity: domain.SeverityInfo,
		Details:  [][]string{{"Extension", "Version", "Schema"}},
	}

	count := 0
	for rows.Next() {
		var name, version, schema string
		if err := rows.Scan(&name, &version, &schema); err != nil {
			return nil, err
		}
		result.Details = append(result.Details, []string{name, version, schema})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result.Info(fmt.Sprintf("Found %d installed extension(s); review for unauthorized extensions", count))
	return result, nil
}

type check_1_9 struct{}

func (c *check_1_9) ID() string          { return "1.9" }
func (c *check_1_9) Reference() *domain.Reference { return domain.CISRef("1.9") }

func (c *check_1_9) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true, SkipPlatforms: domain.ManagedCloud}
}

func (c *check_1_9) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT spcname, pg_tablespace_location(oid) AS location
		FROM pg_tablespace
		WHERE spcname NOT IN ('pg_default', 'pg_global')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &domain.CheckResult{
		Status:   domain.StatusManual,
		Severity: domain.SeverityInfo,
		Details:  [][]string{{"Tablespace", "Location"}},
	}

	count := 0
	for rows.Next() {
		var name, location string
		if err := rows.Scan(&name, &location); err != nil {
			return nil, err
		}
		result.Details = append(result.Details, []string{name, location})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if count == 0 {
		result.Info("No custom tablespaces found")
	} else {
		result.Info(fmt.Sprintf("Found %d custom tablespace(s); verify locations are secure", count))
	}
	return result, nil
}

type check_1_1_1 struct{}

func (c *check_1_1_1) ID() string          { return "1.1.1" }
func (c *check_1_1_1) Reference() *domain.Reference { return domain.CISRef("1.1.1") }

func (c *check_1_1_1) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_1_1) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	if env.Commands["rpm"] {
		return domain.ManualResult("RPM-based system detected; manually run: rpm -qa | grep pgdg"), nil
	}

	if env.HasFilesystem {
		fsys := env.GetFS()
		matches, err := fs.Glob(fsys, "etc/apt/sources.list.d/*pgdg*")
		if err == nil && len(matches) > 0 {
			var names []string
			for _, m := range matches {
				names = append(names, filepath.Base(m))
			}
			result.Pass("PGDG repository files found: " + strings.Join(names, ", "))
			return result, nil
		}

		data, err := fs.ReadFile(fsys, "etc/apt/sources.list")
		if err == nil && strings.Contains(string(data), "pgdg") {
			result.Pass("PGDG repository found in /etc/apt/sources.list")
			return result, nil
		}
	}

	return domain.ManualResult("Unable to determine repository source; manually verify PGDG repository is configured"), nil
}

type check_1_4_1 struct{}

func (c *check_1_4_1) ID() string          { return "1.4.1" }
func (c *check_1_4_1) Reference() *domain.Reference { return domain.CISRef("1.4.1") }

func (c *check_1_4_1) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_4_1) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	fileVersion, err := readPGVersion(ctx, env)
	if errors.Is(err, errNoAccess) {
		result.Status = domain.StatusSkipped
		result.SkipReason = errNoAccess.Error()
		return result, nil
	}
	if err != nil {
		result.Fail("Cannot read PG_VERSION file: " + err.Error())
		return result, nil
	}

	runningVersion := fmt.Sprintf("%d", env.PGVersion)

	if fileVersion == runningVersion {
		result.Pass(fmt.Sprintf("PG_VERSION (%s) matches running version (%s)", fileVersion, runningVersion))
	} else {
		result.Fail(fmt.Sprintf("PG_VERSION (%s) does not match running version (%s)", fileVersion, runningVersion))
	}
	return result, nil
}

type check_1_4_2 struct{}

func (c *check_1_4_2) ID() string          { return "1.4.2" }
func (c *check_1_4_2) Reference() *domain.Reference { return domain.CISRef("1.4.2") }

func (c *check_1_4_2) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_4_2) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	fileVersion, err := readPGVersion(ctx, env)
	if errors.Is(err, errNoAccess) {
		result.Status = domain.StatusSkipped
		result.SkipReason = errNoAccess.Error()
		return result, nil
	}
	if err != nil {
		result.Fail("Cannot read PGDATA/PG_VERSION: " + err.Error())
		return result, nil
	}

	serverVersion, err := domain.ShowSetting(ctx, env.DB, "server_version_num")
	if err != nil {
		return nil, err
	}

	// server_version_num is e.g. "160004" for 16.4 — extract major
	if len(serverVersion) >= 2 {
		major := serverVersion[:len(serverVersion)-4]
		if major == "" {
			major = serverVersion[:1]
		}
		if fileVersion == major {
			result.Pass(fmt.Sprintf("PGDATA/PG_VERSION (%s) is consistent with server version (%s)", fileVersion, serverVersion))
		} else {
			result.Fail(fmt.Sprintf("PGDATA/PG_VERSION (%s) is inconsistent with server_version_num (%s)", fileVersion, serverVersion))
		}
	} else {
		result.Status = domain.StatusManual
		result.Info(fmt.Sprintf("Cannot parse server_version_num: %s; PG_VERSION file says %s", serverVersion, fileVersion))
	}

	return result, nil
}

type check_1_4_3 struct{}

func (c *check_1_4_3) ID() string          { return "1.4.3" }
func (c *check_1_4_3) Reference() *domain.Reference { return domain.CISRef("1.4.3") }

func (c *check_1_4_3) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SQLOnly: true}
}

func (c *check_1_4_3) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	val, err := domain.ShowSetting(ctx, env.DB, "data_checksums")
	if err != nil {
		return nil, err
	}

	result := domain.NewResult(domain.SeverityWarning)
	if val == "on" {
		result.Pass("Data checksums are enabled")
	} else {
		result.Fail("Data checksums are not enabled (current: " + val + ")")
	}
	return result, nil
}

type check_1_4_4 struct{}

func (c *check_1_4_4) ID() string          { return "1.4.4" }
func (c *check_1_4_4) Reference() *domain.Reference { return domain.CISRef("1.4.4") }

func (c *check_1_4_4) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{Filesystem: true, SkipPlatforms: domain.NonBareMetal}
}

func (c *check_1_4_4) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	result := domain.NewResult(domain.SeverityWarning)

	pgWal := filepath.Join(env.DataDir, "pg_wal")
	walInfo, err := fs.Lstat(env.GetFS(), domain.FSPath(pgWal))
	walSymlink := err == nil && walInfo.Mode()&fs.ModeSymlink != 0

	tempTablespaces, err := domain.ShowSetting(ctx, env.DB, "temp_tablespaces")
	if err != nil {
		return nil, err
	}

	if walSymlink && tempTablespaces != "" {
		result.Pass("pg_wal is on separate storage (symlink) and temp_tablespaces is set to: " + tempTablespaces)
	} else {
		if !walSymlink {
			result.Warn("pg_wal is not a symlink; WAL may not be on separate storage")
		}
		if tempTablespaces == "" {
			result.Warn("temp_tablespaces is not set; temporary files may not be on separate storage")
		}
		result.Status = domain.StatusFail
	}
	return result, nil
}

type check_1_4_5 struct{}

func (c *check_1_4_5) ID() string          { return "1.4.5" }
func (c *check_1_4_5) Reference() *domain.Reference { return domain.CISRef("1.4.5") }

func (c *check_1_4_5) Requirements() domain.CheckRequirements {
	return domain.CheckRequirements{SkipPlatforms: domain.ManagedCloud}
}

func (c *check_1_4_5) Run(ctx context.Context, env *domain.Environment) (*domain.CheckResult, error) {
	return domain.ManualResult("Manually audit the storage type used for PostgreSQL data (SSD, SAN, NFS, etc.)"), nil
}
