package checker

import (
	"context"
	"slices"
	"strings"
)

// Severity represents the severity level of a check finding.
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

// Status represents the outcome of running a check.
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

// CheckRequirements declares what a check needs to run.
type CheckRequirements struct {
	// SQL-only check — no filesystem or command access needed.
	SQLOnly bool
	// Requires filesystem access to PGDATA.
	Filesystem bool
	// System commands required (e.g., "systemctl", "lsblk").
	Commands []string
	// Minimum PostgreSQL version (major, e.g., 13).
	MinPGVersion int
	// Requires superuser or equivalent privileges.
	Superuser bool
	// Requires pg_monitor membership or equivalent.
	PGMonitor bool
}

// CheckResult holds the output of a single check execution.
type CheckResult struct {
	Status     Status
	Severity   Severity
	Messages   []Message
	Details    [][]string // Tabular data: first row is headers.
	SkipReason string
}

// Message is a single finding within a check.
type Message struct {
	Level   string // SUCCESS, FAILURE, WARNING, CRITICAL, INFO
	Content string
}

// Check is the interface every security check must implement.
type Check interface {
	// ID returns the check identifier (e.g., "1.4.3").
	ID() string
	// Requirements declares what the check needs to run.
	Requirements() CheckRequirements
	// Run executes the check against the given environment.
	Run(ctx context.Context, env *Environment) (*CheckResult, error)
}

// Environment bundles all runtime context a check might need.
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
	Commands      map[string]bool // command name → available
	IsContainer   bool
	OS            string // runtime.GOOS

	// Databases to check
	Databases        []string
	AllowDatabases   []string
	ExcludeDatabases []string

	// Parsed HBA entries (populated before HBA checks run)
	HBAEntries []HBAEntry
	HBALoaded  bool

	// Cached data
	Superusers []string // rolnames with rolsuper=true
}

// DBQuerier abstracts database access for testing.
type DBQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// Row abstracts pgx.Row.
type Row interface {
	Scan(dest ...any) error
}

// Rows abstracts pgx.Rows.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

// HBAEntry represents a parsed pg_hba.conf line.
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

// ErrPermissionDenied is returned when a query fails due to insufficient privileges.
var ErrPermissionDenied = errPermission{}

type errPermission struct{}

func (errPermission) Error() string { return "permission denied" }

// ShouldCheckDB returns true if the given database should be included.
func (e *Environment) ShouldCheckDB(db string) bool {
	if len(e.AllowDatabases) > 0 {
		return slices.Contains(e.AllowDatabases, db)
	}
	return !slices.Contains(e.ExcludeDatabases, db)
}
