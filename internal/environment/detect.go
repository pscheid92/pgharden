package environment

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/connection"
)

// Detect probes the runtime environment and builds a checker.Environment.
func Detect(ctx context.Context, conn *pgx.Conn, db *connection.ConnWrapper) (*checker.Environment, error) {
	env := &checker.Environment{
		DB:       db,
		Commands: make(map[string]bool),
		OS:       runtime.GOOS,
	}

	// Detect PG version
	var versionStr string
	if err := conn.QueryRow(ctx, "SELECT version()").Scan(&versionStr); err != nil {
		return nil, err
	}
	env.PGVersionFull = versionStr
	env.PGVersion = parseMajorVersion(versionStr)

	// Detect privileges
	privs, err := connection.DetectPrivileges(ctx, conn)
	if err != nil {
		return nil, err
	}
	env.IsSuperuser = privs.IsSuperuser
	env.IsRDSSuperuser = privs.IsRDSSuperuser
	env.IsPGMonitor = privs.IsPGMonitor

	// Detect data directory
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&env.DataDir); err == nil {
		// Check if we can access it
		if _, err := os.Stat(env.DataDir); err == nil {
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
	rows, err := conn.Query(ctx, "SELECT datname FROM pg_database WHERE datallowconn ORDER BY datname")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dbname string
			if err := rows.Scan(&dbname); err == nil {
				env.Databases = append(env.Databases, dbname)
			}
		}
	}

	// Get superuser list
	srows, err := conn.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY rolname")
	if err == nil {
		defer srows.Close()
		for srows.Next() {
			var rolname string
			if err := srows.Scan(&rolname); err == nil {
				env.Superusers = append(env.Superusers, rolname)
			}
		}
	}

	return env, nil
}

func parseMajorVersion(versionStr string) int {
	re := regexp.MustCompile(`PostgreSQL (\d+)`)
	matches := re.FindStringSubmatch(versionStr)
	if len(matches) >= 2 {
		v, _ := strconv.Atoi(matches[1])
		return v
	}
	return 0
}

func detectContainer() bool {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check cgroup for container indicators
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if regexp.MustCompile(`docker|kubepods|containerd`).MatchString(content) {
			return true
		}
	}

	return false
}
