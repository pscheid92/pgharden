package section1

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

func init() {
	checker.Register(&check11{})
	checker.Register(&check12{})
	checker.Register(&check13{})
	checker.Register(&check15{})
	checker.Register(&check16{})
	checker.Register(&check17{})
	checker.Register(&check18{})
	checker.Register(&check19{})
	checker.Register(&check111{})
	checker.Register(&check141{})
	checker.Register(&check142{})
	checker.Register(&check143{})
	checker.Register(&check144{})
	checker.Register(&check145{})
}

// check11 — 1.1: Verify PostgreSQL packages are obtained from authorized repositories
type check11 struct{}

func (c *check11) ID() string { return "1.1" }

func (c *check11) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check11) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	return &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
		Messages: []checker.Message{
			{Level: "INFO", Content: "Manually verify that PostgreSQL packages are obtained from authorized repositories"},
		},
	}, nil
}

// check12 — 1.2: Verify PostgreSQL systemd service is enabled
type check12 struct{}

func (c *check12) ID() string { return "1.2" }

func (c *check12) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"systemctl"}}
}

func (c *check12) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	out, err := exec.CommandContext(ctx, "systemctl", "is-enabled", "postgresql").CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		// Try with wildcard pattern
		out2, err2 := exec.CommandContext(ctx, "bash", "-c", "systemctl is-enabled postgresql*").CombinedOutput()
		output2 := strings.TrimSpace(string(out2))
		if err2 != nil || !strings.Contains(output2, "enabled") {
			result.Status = checker.StatusFail
			result.Messages = append(result.Messages, checker.Message{
				Level:   "FAILURE",
				Content: "PostgreSQL systemd service is not enabled: " + output,
			})
			return result, nil
		}
		output = output2
	}

	if strings.Contains(output, "enabled") {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "PostgreSQL systemd service is enabled",
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "PostgreSQL systemd service is not enabled: " + output,
		})
	}
	return result, nil
}

// check13 — 1.3: Verify data cluster is initialized
type check13 struct{}

func (c *check13) ID() string { return "1.3" }

func (c *check13) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check13) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	pgVersionFile := filepath.Join(env.DataDir, "PG_VERSION")
	if _, err := os.Stat(pgVersionFile); err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "PG_VERSION file not found in PGDATA: " + pgVersionFile,
		})
		return result, nil
	}

	result.Status = checker.StatusPass
	result.Messages = append(result.Messages, checker.Message{
		Level:   "SUCCESS",
		Content: "Data cluster is initialized (PG_VERSION exists in " + env.DataDir + ")",
	})
	return result, nil
}

// check15 — 1.5: Verify PostgreSQL is at the latest available version
type check15 struct{}

func (c *check15) ID() string { return "1.5" }

func (c *check15) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check15) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	return &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
		Messages: []checker.Message{
			{Level: "INFO", Content: "Manually verify PostgreSQL is at the latest available version. Running: " + env.PGVersionFull},
		},
	}, nil
}

// check16 — 1.6: Verify PGPASSWORD is not set in shell profiles
type check16 struct{}

func (c *check16) ID() string { return "1.6" }

func (c *check16) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check16) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	profileFiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/environment",
	}

	// Check common home directories for the postgres user
	homeGuesses := []string{"/var/lib/postgresql", "/var/lib/pgsql", "/home/postgres"}
	for _, home := range homeGuesses {
		profileFiles = append(profileFiles,
			home+"/.bashrc",
			home+"/.bash_profile",
			home+"/.profile",
		)
	}

	var found []string
	for _, pf := range profileFiles {
		data, err := os.ReadFile(pf)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "PGPASSWORD") {
			found = append(found, pf)
		}
	}

	if len(found) > 0 {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: "PGPASSWORD found in shell profile(s): " + strings.Join(found, ", "),
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "PGPASSWORD not found in any checked shell profile",
		})
	}
	return result, nil
}

// check17 — 1.7: Verify PGPASSWORD is not set in process environments
type check17 struct{}

func (c *check17) ID() string { return "1.7" }

func (c *check17) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check17) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	if env.OS != "linux" {
		result.Status = checker.StatusSkipped
		result.SkipReason = "Process environment check only available on Linux"
		return result, nil
	}

	// Scan /proc/*/environ for PGPASSWORD
	matches, err := filepath.Glob("/proc/[0-9]*/environ")
	if err != nil {
		result.Status = checker.StatusSkipped
		result.SkipReason = "Cannot enumerate /proc entries: " + err.Error()
		return result, nil
	}

	var pidsWithPassword []string
	for _, envFile := range matches {
		data, err := os.ReadFile(envFile)
		if err != nil {
			continue // permission denied is expected for other users' processes
		}
		if strings.Contains(string(data), "PGPASSWORD") {
			// Extract PID from path
			parts := strings.Split(envFile, "/")
			if len(parts) >= 3 {
				pidsWithPassword = append(pidsWithPassword, parts[2])
			}
		}
	}

	if len(pidsWithPassword) > 0 {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: fmt.Sprintf("PGPASSWORD found in environment of %d process(es): PIDs %s", len(pidsWithPassword), strings.Join(pidsWithPassword, ", ")),
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "PGPASSWORD not found in any process environment",
		})
	}
	return result, nil
}

// check18 — 1.8: Audit installed extensions
type check18 struct{}

func (c *check18) ID() string { return "1.8" }

func (c *check18) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check18) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT e.extname, e.extversion, n.nspname
		FROM pg_extension e
		JOIN pg_namespace n ON e.extnamespace = n.oid
		ORDER BY e.extname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
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

	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d installed extension(s); review for unauthorized extensions", count),
	})
	return result, nil
}

// check19 — 1.9: Audit custom tablespaces
type check19 struct{}

func (c *check19) ID() string { return "1.9" }

func (c *check19) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check19) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT spcname, pg_tablespace_location(oid) AS location
		FROM pg_tablespace
		WHERE spcname NOT IN ('pg_default', 'pg_global')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
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
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: "No custom tablespaces found",
		})
	} else {
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: fmt.Sprintf("Found %d custom tablespace(s); verify locations are secure", count),
		})
	}
	return result, nil
}

// check111 — 1.1.1: Verify PGDG repository is configured
type check111 struct{}

func (c *check111) ID() string { return "1.1.1" }

func (c *check111) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check111) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	// Try RPM-based check
	if env.Commands["rpm"] {
		result.Status = checker.StatusManual
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: "RPM-based system detected; manually run: rpm -qa | grep pgdg",
		})
		return result, nil
	}

	// Try DEB-based check
	if env.HasFilesystem {
		matches, err := filepath.Glob("/etc/apt/sources.list.d/*pgdg*")
		if err == nil && len(matches) > 0 {
			var names []string
			for _, m := range matches {
				names = append(names, filepath.Base(m))
			}
			result.Status = checker.StatusPass
			result.Messages = append(result.Messages, checker.Message{
				Level:   "SUCCESS",
				Content: "PGDG repository files found: " + strings.Join(names, ", "),
			})
			return result, nil
		}

		// Check sources.list
		data, err := os.ReadFile("/etc/apt/sources.list")
		if err == nil && strings.Contains(string(data), "pgdg") {
			result.Status = checker.StatusPass
			result.Messages = append(result.Messages, checker.Message{
				Level:   "SUCCESS",
				Content: "PGDG repository found in /etc/apt/sources.list",
			})
			return result, nil
		}
	}

	result.Status = checker.StatusManual
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: "Unable to determine repository source; manually verify PGDG repository is configured",
	})
	return result, nil
}

// check141 — 1.4.1: Verify PG_VERSION matches running version
type check141 struct{}

func (c *check141) ID() string { return "1.4.1" }

func (c *check141) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check141) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	pgVersionFile := filepath.Join(env.DataDir, "PG_VERSION")
	data, err := os.ReadFile(pgVersionFile)
	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Cannot read PG_VERSION file: " + err.Error(),
		})
		return result, nil
	}

	fileVersion := strings.TrimSpace(string(data))
	runningVersion := fmt.Sprintf("%d", env.PGVersion)

	if fileVersion == runningVersion {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: fmt.Sprintf("PG_VERSION (%s) matches running version (%s)", fileVersion, runningVersion),
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: fmt.Sprintf("PG_VERSION (%s) does not match running version (%s)", fileVersion, runningVersion),
		})
	}
	return result, nil
}

// check142 — 1.4.2: Verify PGDATA/PG_VERSION consistency with server
type check142 struct{}

func (c *check142) ID() string { return "1.4.2" }

func (c *check142) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check142) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	pgVersionFile := filepath.Join(env.DataDir, "PG_VERSION")
	data, err := os.ReadFile(pgVersionFile)
	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Cannot read PGDATA/PG_VERSION: " + err.Error(),
		})
		return result, nil
	}

	fileVersion := strings.TrimSpace(string(data))

	// Get the version from the server
	var serverVersion string
	if err := env.DB.QueryRow(ctx, "SHOW server_version_num").Scan(&serverVersion); err != nil {
		return nil, err
	}

	// server_version_num is e.g. "160004" for 16.4 — extract major
	if len(serverVersion) >= 2 {
		major := serverVersion[:len(serverVersion)-4]
		if major == "" {
			major = serverVersion[:1]
		}
		if fileVersion == major {
			result.Status = checker.StatusPass
			result.Messages = append(result.Messages, checker.Message{
				Level:   "SUCCESS",
				Content: fmt.Sprintf("PGDATA/PG_VERSION (%s) is consistent with server version (%s)", fileVersion, serverVersion),
			})
		} else {
			result.Status = checker.StatusFail
			result.Messages = append(result.Messages, checker.Message{
				Level:   "FAILURE",
				Content: fmt.Sprintf("PGDATA/PG_VERSION (%s) is inconsistent with server_version_num (%s)", fileVersion, serverVersion),
			})
		}
	} else {
		result.Status = checker.StatusManual
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: fmt.Sprintf("Cannot parse server_version_num: %s; PG_VERSION file says %s", serverVersion, fileVersion),
		})
	}

	return result, nil
}

// check143 — 1.4.3: Verify data checksums are enabled
type check143 struct{}

func (c *check143) ID() string { return "1.4.3" }

func (c *check143) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check143) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var val string
	if err := env.DB.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name = 'data_checksums'").Scan(&val); err != nil {
		return nil, err
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}
	if val == "on" {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "Data checksums are enabled",
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Data checksums are not enabled (current: " + val + ")",
		})
	}
	return result, nil
}

// check144 — 1.4.4: Verify WAL and temp files are on separate storage
type check144 struct{}

func (c *check144) ID() string { return "1.4.4" }

func (c *check144) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check144) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	// Check if pg_wal is a symlink (separate storage)
	pgWal := filepath.Join(env.DataDir, "pg_wal")
	walInfo, err := os.Lstat(pgWal)
	walSymlink := err == nil && walInfo.Mode()&os.ModeSymlink != 0

	// Check temp_tablespaces
	var tempTablespaces string
	if err := env.DB.QueryRow(ctx, "SHOW temp_tablespaces").Scan(&tempTablespaces); err != nil {
		return nil, err
	}

	if walSymlink && tempTablespaces != "" {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "pg_wal is on separate storage (symlink) and temp_tablespaces is set to: " + tempTablespaces,
		})
	} else {
		if !walSymlink {
			result.Messages = append(result.Messages, checker.Message{
				Level:   "WARNING",
				Content: "pg_wal is not a symlink; WAL may not be on separate storage",
			})
		}
		if tempTablespaces == "" {
			result.Messages = append(result.Messages, checker.Message{
				Level:   "WARNING",
				Content: "temp_tablespaces is not set; temporary files may not be on separate storage",
			})
		}
		result.Status = checker.StatusFail
	}
	return result, nil
}

// check145 — 1.4.5: Audit storage type
type check145 struct{}

func (c *check145) ID() string { return "1.4.5" }

func (c *check145) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{}
}

func (c *check145) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	return &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
		Messages: []checker.Message{
			{Level: "INFO", Content: "Manually audit the storage type used for PostgreSQL data (SSD, SAN, NFS, etc.)"},
		},
	}, nil
}
