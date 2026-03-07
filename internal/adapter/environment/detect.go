package environment

import (
	"context"
	"io/fs"
	"log/slog"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/domain"
	"github.com/pgharden/pgharden/internal/adapter/postgres"
)

var (
	pgVersionRe = regexp.MustCompile(`PostgreSQL (\d+)`)
	containerRe = regexp.MustCompile(`docker|kubepods|containerd`)
)

func Detect(ctx context.Context, db domain.DBQuerier) (*domain.Environment, error) {
	env := &domain.Environment{DB: db, Commands: make(map[string]bool), OS: runtime.GOOS}

	// Detect PG version
	var versionStr string
	if err := db.QueryRow(ctx, "SELECT version()").Scan(&versionStr); err != nil {
		return nil, err
	}
	env.PGVersionFull = versionStr
	env.PGVersion = parseMajorVersion(versionStr)

	// Detect privileges
	privileges, err := postgres.DetectPrivileges(ctx, db)
	if err != nil {
		return nil, err
	}
	env.IsSuperuser = privileges.IsSuperuser
	env.IsRDSSuperuser = privileges.IsRDSSuperuser
	env.IsPGMonitor = privileges.IsPGMonitor

	// Detect data directory (always query for reporting, but don't enable filesystem)
	var dataDir string
	if err := db.QueryRow(ctx, "SHOW data_directory").Scan(&dataDir); err == nil {
		env.DataDir = dataDir
	}

	// Detect platform
	env.Platform = detectPlatform(ctx, db, env)

	// Get database list
	dbRows, err := db.Query(ctx, "SELECT datname FROM pg_database WHERE datallowconn ORDER BY datname")
	if err != nil {
		slog.Warn("failed to list databases", "error", err)
	} else {
		if env.Databases, err = pgx.CollectRows(dbRows, pgx.RowTo[string]); err != nil {
			slog.Warn("failed to collect databases", "error", err)
		}
	}

	// Get superuser list
	suRows, err := db.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY rolname")
	if err != nil {
		slog.Warn("failed to list superusers", "error", err)
	} else {
		if env.Superusers, err = pgx.CollectRows(suRows, pgx.RowTo[string]); err != nil {
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

func detectPlatform(ctx context.Context, db domain.DBQuerier, env *domain.Environment) string {
	// RDS/Aurora: rds_superuser role exists
	if env.IsRDSSuperuser {
		return detectRDSOrAurora(ctx, db)
	}
	var rdsCount int
	if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM pg_roles WHERE rolname = 'rds_superuser'").Scan(&rdsCount); err == nil && rdsCount > 0 {
		return detectRDSOrAurora(ctx, db)
	}

	// Zalando operator: archive_command or restore_command references /controller/manager
	for _, setting := range []string{"archive_command", "restore_command"} {
		var val string
		if err := db.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name = $1", setting).Scan(&val); err == nil {
			if strings.Contains(val, "/controller/manager") {
				return domain.PlatformZalando
			}
		}
	}

	// Local container detection (when running inside the same container)
	if isLocalContainer(env.GetFS()) {
		return domain.PlatformContainer
	}

	return domain.PlatformBareMetal
}

func detectRDSOrAurora(ctx context.Context, db domain.DBQuerier) string {
	var engine string
	// aurora_version() exists only on Aurora
	if err := db.QueryRow(ctx, "SELECT aurora_version()").Scan(&engine); err == nil {
		return domain.PlatformAurora
	}
	return domain.PlatformRDS
}

// EnableLocal enables filesystem and OS command checks on the environment.
// Only call this when pgharden is running on the same host as PostgreSQL.
func EnableLocal(env *domain.Environment) {
	if env.DataDir != "" {
		if _, err := fs.Stat(env.GetFS(), domain.FSPath(env.DataDir)); err == nil {
			env.HasFilesystem = true
		}
	}

	for _, cmd := range []string{"systemctl", "sh", "rpm", "dpkg", "lsblk", "pgbackrest", "curl", "ps", "fips-mode-setup"} {
		if _, err := exec.LookPath(cmd); err == nil {
			env.Commands[cmd] = true
		}
	}
}

func isLocalContainer(fsys fs.FS) bool {
	if _, err := fs.Stat(fsys, ".dockerenv"); err == nil {
		return true
	}

	data, err := fs.ReadFile(fsys, "proc/1/cgroup")
	return err == nil && containerRe.MatchString(string(data))
}
