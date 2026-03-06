package report

import "time"

// Report is the top-level output structure.
type Report struct {
	Metadata   Metadata          `json:"metadata"`
	Summary    Summary           `json:"summary"`
	Categories []CategoryReport  `json:"categories"`
}

// Metadata holds information about the assessment run.
type Metadata struct {
	Timestamp       time.Time `json:"timestamp"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Database        string    `json:"database"`
	PGVersion       string    `json:"pg_version"`
	PGVersionMajor  int       `json:"pg_version_major"`
	EnvironmentType string    `json:"environment_type"` // bare-metal, container, rds, etc.
	ToolVersion     string    `json:"tool_version"`
	IsSuperuser     bool      `json:"is_superuser"`
}

// Summary holds aggregate counts.
type Summary struct {
	Total    int            `json:"total"`
	Passed   int            `json:"passed"`
	Failed   int            `json:"failed"`
	Skipped  int            `json:"skipped"`
	Manual   int            `json:"manual"`
	BySeverity map[string]int `json:"by_severity"`
}

// CategoryReport groups checks by section.
type CategoryReport struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Checks []CheckReport `json:"checks"`
}

// CheckReport holds the result of a single check.
type CheckReport struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	Messages    []MsgEntry `json:"messages,omitempty"`
	Details     [][]string `json:"details,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	SkipReason  string     `json:"skip_reason,omitempty"`
}

// MsgEntry is a single message in a check result.
type MsgEntry struct {
	Level   string `json:"level"`
	Content string `json:"content"`
}
