package domain

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrPermissionDenied = errors.New("permission denied")

// Platform constants for environment detection.
const (
	PlatformBareMetal = "bare-metal"
	PlatformContainer = "container"
	PlatformZalando   = "zalando"
	PlatformRDS       = "rds"
	PlatformAurora    = "aurora"
)

// Platform skip lists for common platform groupings used in CheckRequirements.SkipPlatforms.
var (
	NonBareMetal = []string{PlatformContainer, PlatformZalando, PlatformRDS, PlatformAurora}
	ManagedCloud = []string{PlatformRDS, PlatformAurora}
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
	SQLOnly       bool     // SQL-only check; no filesystem or command access needed.
	Filesystem    bool     // Requires filesystem access to PGDATA.
	Commands      []string // System commands required (e.g., "systemctl", "lsblk").
	MinPGVersion  int      // Minimum PostgreSQL version (major, e.g., 13).
	Superuser     bool     // Requires superuser or equivalent privileges.
	PGMonitor     bool     // Requires pg_monitor membership or equivalent.
	SkipPlatforms []string // Platforms where this check is not applicable (e.g., "rds", "aurora").
}

func NewResult(sev Severity) *CheckResult {
	return &CheckResult{Severity: sev}
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

// Message levels.
const (
	LevelSuccess  = "SUCCESS"
	LevelFailure  = "FAILURE"
	LevelWarning  = "WARNING"
	LevelCritical = "CRITICAL"
	LevelInfo     = "INFO"
)

func (r *CheckResult) Pass(msg string) {
	r.Status = StatusPass
	r.Messages = append(r.Messages, Message{Level: LevelSuccess, Content: msg})
}

func (r *CheckResult) Fail(msg string) {
	r.Status = StatusFail
	r.Messages = append(r.Messages, Message{Level: LevelFailure, Content: msg})
}

func (r *CheckResult) Critical(msg string) {
	r.Status = StatusFail
	r.Messages = append(r.Messages, Message{Level: LevelCritical, Content: msg})
}

func (r *CheckResult) FailWarn(msg string) {
	r.Status = StatusFail
	r.Messages = append(r.Messages, Message{Level: LevelWarning, Content: msg})
}

func (r *CheckResult) Warn(msg string) {
	r.Messages = append(r.Messages, Message{Level: LevelWarning, Content: msg})
}

func (r *CheckResult) Info(msg string) {
	r.Messages = append(r.Messages, Message{Level: LevelInfo, Content: msg})
}

func ManualResult(msg string) *CheckResult {
	return &CheckResult{
		Status:   StatusManual,
		Severity: SeverityInfo,
		Messages: []Message{{Level: LevelInfo, Content: msg}},
	}
}

func SkippedHBA(err error) *CheckResult {
	return &CheckResult{
		Status:     StatusSkipped,
		SkipReason: "Cannot load pg_hba.conf: " + err.Error(),
	}
}

type Check interface {
	ID() string
	Requirements() CheckRequirements
	Run(ctx context.Context, env *Environment) (*CheckResult, error)
}

type RunResult struct {
	CheckID string
	Result  *CheckResult
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
	FS            fs.FS          // Filesystem for checks; nil defaults to os.DirFS("/")
	Cmd           CommandRunner  // Command runner for checks; nil defaults to real exec.
	Commands      map[string]bool
	Platform      string // detected or user-specified platform
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

// IsManagedCloud returns true if the platform is a managed cloud service (RDS or Aurora).
func (e *Environment) IsManagedCloud() bool {
	return e.Platform == PlatformRDS || e.Platform == PlatformAurora
}

// GetFS returns the environment's filesystem, defaulting to the real OS root.
func (e *Environment) GetFS() fs.FS {
	if e.FS != nil {
		return e.FS
	}
	return os.DirFS("/")
}

// CommandRunner abstracts OS command execution. Production uses osCommandRunner;
// tests inject a mock.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type osCommandRunner struct{}

func (r *osCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// GetCmd returns the environment's command runner, defaulting to real exec.
func (e *Environment) GetCmd() CommandRunner {
	if e.Cmd != nil {
		return e.Cmd
	}
	return &osCommandRunner{}
}

// FSPath converts an absolute path to an fs.FS-relative path by stripping the leading "/".
func FSPath(abs string) string {
	return strings.TrimPrefix(abs, "/")
}

func (e *Environment) ShouldCheckDB(db string) bool {
	if len(e.AllowDatabases) > 0 {
		return slices.Contains(e.AllowDatabases, db)
	}
	return !slices.Contains(e.ExcludeDatabases, db)
}

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

func ShowSetting(ctx context.Context, db DBQuerier, name string) (string, error) {
	var val string
	err := db.QueryRow(ctx, "SELECT setting FROM pg_settings WHERE name = $1", name).Scan(&val)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "42501" {
		return "", ErrPermissionDenied
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPermissionDenied
	}
	if err != nil {
		return "", err
	}

	return val, nil
}

func SectionID(checkID string) string {
	if dot := strings.IndexByte(checkID, '.'); dot >= 0 {
		return checkID[:dot]
	}
	return checkID
}

func SortChecks(checks []Check) {
	sort.Slice(checks, func(i, j int) bool {
		return CompareCheckIDs(checks[i].ID(), checks[j].ID()) < 0
	})
}

func CompareCheckIDs(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := max(len(partsB), len(partsA))

	for i := 0; i < maxLen; i++ {
		var na, nb int
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na != nb {
			return na - nb
		}
	}
	return 0
}

func SkippedPermission(setting string) *CheckResult {
	return &CheckResult{Status: StatusSkipped, SkipReason: "Insufficient privileges to read " + setting}
}
