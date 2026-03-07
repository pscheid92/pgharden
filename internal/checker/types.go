package checker

import (
	"context"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusSkipped
	StatusManual
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusSkipped:
		return "SKIPPED"
	case StatusManual:
		return "MANUAL"
	default:
		return "UNKNOWN"
	}
}

type CheckRequirements struct {
	SQLOnly      bool     // SQL-only check; no filesystem or command access needed.
	Filesystem   bool     // Requires filesystem access to PGDATA.
	Commands     []string // System commands required (e.g., "systemctl", "lsblk").
	MinPGVersion int      // Minimum PostgreSQL version (major, e.g., 13).
	Superuser    bool     // Requires superuser or equivalent privileges.
	PGMonitor    bool     // Requires pg_monitor membership or equivalent.
}

type CheckResult struct {
	Status     Status
	Severity   Severity
	Messages   []Message
	Details    [][]string // Tabular data: the first row contains headers
	SkipReason string
}

type Message struct {
	Level   string // SUCCESS, FAILURE, WARNING, CRITICAL, INFO
	Content string
}

type Check interface {
	ID() string
	Requirements() CheckRequirements
	Run(ctx context.Context, env *Environment) (*CheckResult, error)
}

type Environment struct {
	DB            DBQuerier
	PGVersion     int    // Major version (e.g., 15)
	PGVersionFull string // Full version string from SELECT version()
	DataDir       string // PGDATA path

	// Privileges
	IsSuperuser    bool
	IsRDSSuperuser bool
	IsPGMonitor    bool

	// Capabilities
	HasFilesystem bool
	Commands      map[string]bool
	IsContainer   bool
	OS            string

	// Databases to check
	Databases        []string
	AllowDatabases   []string
	ExcludeDatabases []string

	// Parsed HBA entries (populated before HBA checks run)
	HBAEntries []HBAEntry
	HBALoaded  bool

	// Cached data
	Superusers []string
}

// DBQuerier abstracts database access. Satisfied by *pgx.Conn and pgxmock.
type DBQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type HBAEntry struct {
	LineNumber int
	Type       string // local, host, hostssl, hostnossl, hostgssenc, hostnogssenc
	Database   string
	User       string
	Address    string
	Netmask    string
	Method     string
	Options    string
}

// ShowSetting runs SHOW <name> and returns the value. If the query fails due to
// permission denied, it returns ("", ErrPermissionDenied) so checks can skip gracefully.
func ShowSetting(ctx context.Context, db DBQuerier, name string) (string, error) {
	var val string
	if err := db.QueryRow(ctx, "SHOW "+name).Scan(&val); err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return "", ErrPermissionDenied
		}
		return "", err
	}
	return val, nil
}

// SkippedPermission returns a SKIPPED CheckResult for permission errors.
func SkippedPermission(setting string) *CheckResult {
	return &CheckResult{
		Status:     StatusSkipped,
		SkipReason: "Insufficient privileges to read " + setting,
	}
}

var ErrPermissionDenied = errPermission{}

type errPermission struct{}

func (errPermission) Error() string { return "permission denied" }

func (e *Environment) ShouldCheckDB(db string) bool {
	if len(e.AllowDatabases) > 0 {
		return slices.Contains(e.AllowDatabases, db)
	}
	return !slices.Contains(e.ExcludeDatabases, db)
}
