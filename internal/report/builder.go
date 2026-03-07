package report

import (
	"strings"
	"time"

	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/labels"
)

// Build constructs a Report from check results and environment info.
func Build(results []checker.RunResult, env *checker.Environment, meta Metadata) *Report {
	meta.Timestamp = time.Now().UTC()
	if env != nil {
		meta.PGVersion = env.PGVersionFull
		meta.PGVersionMajor = env.PGVersion
		meta.IsSuperuser = env.IsSuperuser
		if env.IsContainer {
			meta.EnvironmentType = "container"
		} else {
			meta.EnvironmentType = "bare-metal"
		}
	}

	r := &Report{
		Metadata: meta,
		Summary: Summary{
			BySeverity: make(map[string]int),
		},
	}

	// Group results by section
	sections := make(map[string]*CategoryReport)
	var sectionOrder []string

	for _, rr := range results {
		sectionID := rr.CheckID
		if dot := strings.IndexByte(sectionID, '.'); dot >= 0 {
			sectionID = sectionID[:dot]
		}

		cat, ok := sections[sectionID]
		if !ok {
			cat = &CategoryReport{
				ID:    sectionID,
				Title: labels.SectionTitle(sectionID),
			}
			sections[sectionID] = cat
			sectionOrder = append(sectionOrder, sectionID)
		}

		cr := CheckReport{
			ID:          rr.CheckID,
			Title:       labels.CheckTitle(rr.CheckID),
			Description: labels.CheckDescription(rr.CheckID),
		}

		if rr.Err != nil {
			cr.Status = "ERROR"
			cr.Messages = []MsgEntry{{Level: "ERROR", Content: rr.Err.Error()}}
			r.Summary.Failed++
		} else if rr.Result != nil {
			cr.Status = rr.Result.Status.String()
			cr.Severity = rr.Result.Severity.String()
			cr.SkipReason = rr.Result.SkipReason
			cr.Details = rr.Result.Details

			for _, m := range rr.Result.Messages {
				cr.Messages = append(cr.Messages, MsgEntry{Level: m.Level, Content: m.Content})
			}

			switch rr.Result.Status {
			case checker.StatusPass:
				r.Summary.Passed++
			case checker.StatusFail:
				r.Summary.Failed++
				r.Summary.BySeverity[cr.Severity]++
			case checker.StatusSkipped:
				r.Summary.Skipped++
			case checker.StatusManual:
				r.Summary.Manual++
			}
		}

		r.Summary.Total++
		cat.Checks = append(cat.Checks, cr)
	}

	for _, sid := range sectionOrder {
		r.Categories = append(r.Categories, *sections[sid])
	}

	return r
}
