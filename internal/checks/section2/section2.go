//go:build !windows

package section2

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pgharden/pgharden/internal/checker"
)

func Checks() []checker.Check {
	return []checker.Check{
		&check_2_1{},
		&check_2_2{},
		&check_2_3{},
		&check_2_4{},
		&check_2_5{},
		&check_2_6{},
		&check_2_7{},
		&check_2_8{},
	}
}

type check_2_1 struct{}

func (c *check_2_1) ID() string { return "2.1" }

func (c *check_2_1) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Commands: []string{"sh"}, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_1) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityWarning)

	out, err := exec.CommandContext(ctx, "sh", "-c", "umask").CombinedOutput()
	if err != nil {
		result.Fail("Cannot determine umask: " + err.Error())
		return result, nil
	}

	umask := strings.TrimSpace(string(out))
	if umask == "0077" || umask == "077" {
		result.Pass("umask is set correctly: " + umask)
	} else {
		result.Fail("umask is " + umask + " (expected 0077)")
	}
	return result, nil
}

type check_2_2 struct{}

func (c *check_2_2) ID() string { return "2.2" }

func (c *check_2_2) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_2) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityWarning)

	dynPath, err := checker.ShowSetting(ctx, env.DB, "dynamic_library_path")
	if err != nil {
		return nil, err
	}

	var libdir string
	if err := env.DB.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name = 'pkglibdir'").Scan(&libdir); err != nil {
		_ = env.DB.QueryRow(ctx, "SELECT pg_config('PKGLIBDIR')").Scan(&libdir)
	}

	fsys := env.GetFS()
	dirs := strings.Split(dynPath, ":")
	var problems []string

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "$libdir" && libdir != "" {
			dir = libdir
		} else if dir == "$libdir" {
			continue
		}

		info, err := fs.Stat(fsys, checker.FSPath(dir))
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
		for _, p := range problems {
			result.Fail(p)
		}
	} else {
		result.Pass("Extension directory permissions are correct for: " + dynPath)
	}
	return result, nil
}

type check_2_3 struct{}

func (c *check_2_3) ID() string { return "2.3" }

func (c *check_2_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityWarning)

	fsys := env.GetFS()
	searchDirs := []string{"/home", "/var/lib/postgresql", "/var/lib/pgsql", "/root"}

	var problems []string

	for _, base := range searchDirs {
		entries, err := fs.ReadDir(fsys, checker.FSPath(base))
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

			info, err := fs.Lstat(fsys, checker.FSPath(histPath))
			if err != nil {
				continue
			}

			if info.Mode()&fs.ModeSymlink != 0 {
				target, err := fs.ReadLink(fsys, checker.FSPath(histPath))
				if err == nil && target == "/dev/null" {
					continue // Good: symlinked to /dev/null
				}
			}

			problems = append(problems, histPath)
		}

		if base == "/root" {
			continue
		}
	}

	if len(problems) > 0 {
		result.Fail(".psql_history exists and is not linked to /dev/null: " + strings.Join(problems, ", "))
	} else {
		result.Pass("No unprotected .psql_history files found")
	}
	return result, nil
}

type check_2_4 struct{}

func (c *check_2_4) ID() string { return "2.4" }

func (c *check_2_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityCritical)

	fsys := env.GetFS()
	searchDirs := []string{"/home", "/var/lib/postgresql", "/var/lib/pgsql", "/root"}
	var problems []string

	for _, base := range searchDirs {
		entries, err := fs.ReadDir(fsys, checker.FSPath(base))
		if err != nil {
			if base == "/root" {
				checkServiceConf(fsys, "/root/.pg_service.conf", &problems)
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
			checkServiceConf(fsys, confPath, &problems)
		}
	}

	if len(problems) > 0 {
		result.Critical("Passwords found in .pg_service.conf: " + strings.Join(problems, ", "))
	} else {
		result.Pass("No passwords found in .pg_service.conf files")
	}
	return result, nil
}

func checkServiceConf(fsys fs.FS, path string, problems *[]string) {
	data, err := fs.ReadFile(fsys, checker.FSPath(path))
	if err != nil {
		return
	}
	content := strings.ToLower(string(data))
	if strings.Contains(content, "password") {
		*problems = append(*problems, path)
	}
}

type check_2_5 struct{}

func (c *check_2_5) ID() string { return "2.5" }

func (c *check_2_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityCritical)

	hbaFile, err := checker.ShowSetting(ctx, env.DB, "hba_file")
	if err != nil {
		return nil, err
	}

	info, err := fs.Stat(env.GetFS(), checker.FSPath(hbaFile))
	if err != nil {
		result.Fail("Cannot stat pg_hba.conf: " + err.Error())
		return result, nil
	}

	perm := info.Mode().Perm()
	// Acceptable: 0600 (-rw-------) or 0640 (-rw-r-----)
	if perm == 0600 || perm == 0640 {
		result.Pass(fmt.Sprintf("pg_hba.conf permissions are restrictive: %04o", perm))
	} else {
		result.Critical(fmt.Sprintf("pg_hba.conf has overly permissive mode: %04o (expected 0600 or 0640)", perm))
	}
	return result, nil
}

type check_2_6 struct{}

func (c *check_2_6) ID() string { return "2.6" }

func (c *check_2_6) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_6) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityWarning)

	sockDirs, err := checker.ShowSetting(ctx, env.DB, "unix_socket_directories")
	if err != nil {
		return nil, err
	}

	fsys := env.GetFS()
	var problems []string
	dirs := strings.SplitSeq(sockDirs, ",")

	for dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		info, err := fs.Stat(fsys, checker.FSPath(dir))
		if err != nil {
			continue
		}

		perm := info.Mode().Perm()
		if perm&0002 != 0 { // world-writable
			problems = append(problems, fmt.Sprintf("%s has world-writable mode: %04o", dir, perm))
		}
	}

	if len(problems) > 0 {
		for _, p := range problems {
			result.Fail(p)
		}
	} else {
		result.Pass("Unix socket directory permissions are acceptable: " + sockDirs)
	}
	return result, nil
}

type check_2_7 struct{}

func (c *check_2_7) ID() string { return "2.7" }

func (c *check_2_7) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_7) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := checker.NewResult(checker.SeverityCritical)

	info, err := fs.Stat(env.GetFS(), checker.FSPath(env.DataDir))
	if err != nil {
		result.Fail("Cannot stat PGDATA directory: " + err.Error())
		return result, nil
	}

	perm := info.Mode().Perm()
	if perm == 0700 {
		result.Pass(fmt.Sprintf("PGDATA permissions are correct: %04o", perm))
	} else {
		result.Critical(fmt.Sprintf("PGDATA has incorrect permissions: %04o (expected 0700)", perm))
	}
	return result, nil
}

type check_2_8 struct{}

func (c *check_2_8) ID() string { return "2.8" }

func (c *check_2_8) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true, SkipPlatforms: checker.NonBareMetal}
}

func (c *check_2_8) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	return checker.ManualResult("Manually verify that all files in " + env.DataDir + " are owned by the postgres OS user"), nil
}
