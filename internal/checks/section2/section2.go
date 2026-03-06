//go:build !windows

package section2

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pgharden/pgharden/internal/checker"
)

func init() {
	checker.Register(&check_2_1{})
	checker.Register(&check_2_2{})
	checker.Register(&check_2_3{})
	checker.Register(&check_2_4{})
	checker.Register(&check_2_5{})
	checker.Register(&check_2_6{})
	checker.Register(&check_2_7{})
	checker.Register(&check_2_8{})
}

// ---------------------------------------------------------------------------
// Check 2.1 – Verify umask is set to 0077
// ---------------------------------------------------------------------------

type check_2_1 struct{}

func (c *check_2_1) ID() string { return "2.1" }

func (c *check_2_1) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"sh"}}
}

func (c *check_2_1) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	out, err := exec.CommandContext(ctx, "sh", "-c", "umask").CombinedOutput()
	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Cannot determine umask: " + err.Error(),
		})
		return result, nil
	}

	umask := strings.TrimSpace(string(out))
	if umask == "0077" || umask == "077" {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "umask is set correctly: " + umask,
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "umask is " + umask + " (expected 0077)",
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 2.2 – Verify extension directory permissions
// ---------------------------------------------------------------------------

type check_2_2 struct{}

func (c *check_2_2) ID() string { return "2.2" }

func (c *check_2_2) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_2) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	var dynPath string
	if err := env.DB.QueryRow(ctx, "SHOW dynamic_library_path").Scan(&dynPath); err != nil {
		return nil, err
	}

	// Replace $libdir with the actual library directory
	var libdir string
	if err := env.DB.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name = 'pkglibdir'").Scan(&libdir); err != nil {
		// Fall back to pg_config if possible
		_ = env.DB.QueryRow(ctx, "SELECT pg_config('PKGLIBDIR')").Scan(&libdir)
	}

	dirs := strings.Split(dynPath, ":")
	var problems []string

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "$libdir" && libdir != "" {
			dir = libdir
		} else if dir == "$libdir" {
			continue
		}

		info, err := os.Stat(dir)
		if err != nil {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		perm := info.Mode().Perm()
		if stat.Uid != 0 {
			problems = append(problems, fmt.Sprintf("%s is not owned by root (uid=%d)", dir, stat.Uid))
		}
		if perm&0022 != 0 {
			problems = append(problems, fmt.Sprintf("%s has overly permissive mode: %04o", dir, perm))
		}
	}

	if len(problems) > 0 {
		result.Status = checker.StatusFail
		for _, p := range problems {
			result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: p})
		}
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "Extension directory permissions are correct for: " + dynPath,
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 2.3 – Verify .psql_history is protected
// ---------------------------------------------------------------------------

type check_2_3 struct{}

func (c *check_2_3) ID() string { return "2.3" }

func (c *check_2_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	// Check common home directories for .psql_history
	searchDirs := []string{"/home", "/var/lib/postgresql", "/var/lib/pgsql", "/root"}

	var problems []string

	for _, base := range searchDirs {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() && base != "/root" {
				continue
			}

			var histPath string
			if base == "/root" {
				histPath = filepath.Join(base, ".psql_history")
			} else {
				histPath = filepath.Join(base, entry.Name(), ".psql_history")
			}

			info, err := os.Lstat(histPath)
			if err != nil {
				continue
			}

			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(histPath)
				if err == nil && target == "/dev/null" {
					continue // Good: symlinked to /dev/null
				}
			}

			// Regular file or symlink to something other than /dev/null
			problems = append(problems, histPath)
		}

		// For /root, we only check the one path
		if base == "/root" {
			continue
		}
	}

	if len(problems) > 0 {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: ".psql_history exists and is not linked to /dev/null: " + strings.Join(problems, ", "),
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "No unprotected .psql_history files found",
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 2.4 – Verify .pg_service.conf has no passwords
// ---------------------------------------------------------------------------

type check_2_4 struct{}

func (c *check_2_4) ID() string { return "2.4" }

func (c *check_2_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	searchDirs := []string{"/home", "/var/lib/postgresql", "/var/lib/pgsql", "/root"}
	var problems []string

	for _, base := range searchDirs {
		entries, err := os.ReadDir(base)
		if err != nil {
			if base == "/root" {
				// Check /root directly
				checkServiceConf("/root/.pg_service.conf", &problems)
			}
			continue
		}

		for _, entry := range entries {
			var confPath string
			if base == "/root" {
				confPath = filepath.Join(base, ".pg_service.conf")
			} else if entry.IsDir() {
				confPath = filepath.Join(base, entry.Name(), ".pg_service.conf")
			} else {
				continue
			}
			checkServiceConf(confPath, &problems)
		}
	}

	if len(problems) > 0 {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: "Passwords found in .pg_service.conf: " + strings.Join(problems, ", "),
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "No passwords found in .pg_service.conf files",
		})
	}
	return result, nil
}

func checkServiceConf(path string, problems *[]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := strings.ToLower(string(data))
	if strings.Contains(content, "password") {
		*problems = append(*problems, path)
	}
}

// ---------------------------------------------------------------------------
// Check 2.5 – Verify pg_hba.conf file permissions
// ---------------------------------------------------------------------------

type check_2_5 struct{}

func (c *check_2_5) ID() string { return "2.5" }

func (c *check_2_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	var hbaFile string
	if err := env.DB.QueryRow(ctx, "SHOW hba_file").Scan(&hbaFile); err != nil {
		return nil, err
	}

	info, err := os.Stat(hbaFile)
	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Cannot stat pg_hba.conf: " + err.Error(),
		})
		return result, nil
	}

	perm := info.Mode().Perm()
	// Acceptable: 0600 (-rw-------) or 0640 (-rw-r-----)
	if perm == 0600 || perm == 0640 {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: fmt.Sprintf("pg_hba.conf permissions are restrictive: %04o", perm),
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: fmt.Sprintf("pg_hba.conf has overly permissive mode: %04o (expected 0600 or 0640)", perm),
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 2.6 – Verify Unix socket directory permissions
// ---------------------------------------------------------------------------

type check_2_6 struct{}

func (c *check_2_6) ID() string { return "2.6" }

func (c *check_2_6) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_6) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	var sockDirs string
	if err := env.DB.QueryRow(ctx, "SHOW unix_socket_directories").Scan(&sockDirs); err != nil {
		return nil, err
	}

	var problems []string
	dirs := strings.SplitSeq(sockDirs, ",")

	for dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		info, err := os.Stat(dir)
		if err != nil {
			continue
		}

		perm := info.Mode().Perm()
		if perm&0002 != 0 { // world-writable
			problems = append(problems, fmt.Sprintf("%s has world-writable mode: %04o", dir, perm))
		}
	}

	if len(problems) > 0 {
		result.Status = checker.StatusFail
		for _, p := range problems {
			result.Messages = append(result.Messages, checker.Message{Level: "FAILURE", Content: p})
		}
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "Unix socket directory permissions are acceptable: " + sockDirs,
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 2.7 – Verify PGDATA directory permissions
// ---------------------------------------------------------------------------

type check_2_7 struct{}

func (c *check_2_7) ID() string { return "2.7" }

func (c *check_2_7) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_7) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityCritical}

	info, err := os.Stat(env.DataDir)
	if err != nil {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "FAILURE",
			Content: "Cannot stat PGDATA directory: " + err.Error(),
		})
		return result, nil
	}

	perm := info.Mode().Perm()
	if perm == 0700 {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: fmt.Sprintf("PGDATA permissions are correct: %04o", perm),
		})
	} else {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "CRITICAL",
			Content: fmt.Sprintf("PGDATA has incorrect permissions: %04o (expected 0700)", perm),
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Check 2.8 – Verify PGDATA file ownership (manual check)
// ---------------------------------------------------------------------------

type check_2_8 struct{}

func (c *check_2_8) ID() string { return "2.8" }

func (c *check_2_8) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_2_8) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	return &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
		Messages: []checker.Message{
			{Level: "INFO", Content: "Manually verify that all files in " + env.DataDir + " are owned by the postgres OS user"},
		},
	}, nil
}
