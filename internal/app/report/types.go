package report

import (
	"time"

	"github.com/pscheid92/pgharden/internal/domain"
)

type Report struct {
	Metadata   Metadata         `json:"metadata"`
	Summary    Summary          `json:"summary"`
	Categories []CategoryReport `json:"categories"`
}

type Metadata struct {
	Timestamp       time.Time `json:"timestamp"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Database        string    `json:"database"`
	PGVersion       string    `json:"pg_version"`
	PGVersionMajor  int       `json:"pg_version_major"`
	Platform        string    `json:"platform"`
	ToolVersion     string    `json:"tool_version"`
	IsSuperuser     bool      `json:"is_superuser"`
	HasFilesystem   bool      `json:"has_filesystem"`
}

type Summary struct {
	Total      int            `json:"total"`
	Passed     int            `json:"passed"`
	Failed     int            `json:"failed"`
	Skipped    int            `json:"skipped"`
	Manual     int            `json:"manual"`
	BySeverity map[string]int `json:"by_severity"`
}

type CategoryReport struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Checks []CheckReport `json:"checks"`
}

type CheckReport struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Reference   *domain.Reference `json:"reference,omitempty"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"`
	Messages    []MsgEntry        `json:"messages,omitempty"`
	Details     [][]string        `json:"details,omitempty"`
	SkipReason  string            `json:"skip_reason,omitempty"`
}

type MsgEntry struct {
	Level   string `json:"level"`
	Content string `json:"content"`
}
