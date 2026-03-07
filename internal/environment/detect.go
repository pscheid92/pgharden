package environment

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/connection"
)

var (
	pgVersionRe = regexp.MustCompile(`PostgreSQL (\d+)`)
	containerRe = regexp.MustCompile(`docker|kubepods|containerd`)
)

func Detect(ctx context.Context, conn *pgx.Conn) (*checker.Environment, error) {
	env := &checker.Environment{DB: conn, Commands: make(map[string]bool), OS: runtime.GOOS}

	// Detect PG version
	var versionStr string
	if err := conn.QueryRow(ctx, "SELECT version()").Scan(&versionStr); err != nil {
		return nil, err
	}
	env.PGVersionFull = versionStr
	env.PGVersion = parseMajorVersion(versionStr)

	// Detect privileges
	privileges, err := connection.DetectPrivileges(ctx, conn)
	if err != nil {
		return nil, err
	}
	env.IsSuperuser = privileges.IsSuperuser
	env.IsRDSSuperuser = privileges.IsRDSSuperuser
	env.IsPGMonitor = privileges.IsPGMonitor

	// Detect data directory
	var dataDir string
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&dataDir); err == nil {
		env.DataDir = dataDir
		if _, err := os.Stat(dataDir); err == nil {
			env.HasFilesystem = true
		}
	}

	// Detect available commands
	for _, cmd := range []string{"systemctl", "rpm", "dpkg", "lsblk", "pgbackrest", "curl"} {
		if _, err := exec.LookPath(cmd); err == nil {
			env.Commands[cmd] = true
		}
	}

	// Detect container environment
	env.IsContainer = detectContainer()

	// Get database list
	dbRows, err := conn.Query(ctx, "SELECT datname FROM pg_database WHERE datallowconn ORDER BY datname")
	if err != nil {
		slog.Warn("failed to list databases", "error", err)
	} else {
		env.Databases, err = pgx.CollectRows(dbRows, pgx.RowTo[string])
		if err != nil {
			slog.Warn("failed to collect databases", "error", err)
		}
	}

	// Get superuser list
	suRows, err := conn.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY rolname")
	if err != nil {
		slog.Warn("failed to list superusers", "error", err)
	} else {
		env.Superusers, err = pgx.CollectRows(suRows, pgx.RowTo[string])
		if err != nil {
			slog.Warn("failed to collect superusers", "error", err)
		}
	}

	return env, nil
}

func parseMajorVersion(versionStr string) int {
	matches := pgVersionRe.FindStringSubmatch(versionStr)
	if len(matches) >= 2 {
		v, _ := strconv.Atoi(matches[1])
		return v
	}
	return 0
}

func detectContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		if containerRe.MatchString(string(data)) {
			return true
		}
	}

	return false
}
