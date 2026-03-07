package report

import (
	"slices"
	"strings"
	"time"

	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/labels"
)

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

	sections := make(map[string]*CategoryReport)

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
		}

		cr := CheckReport{
			ID:          rr.CheckID,
			Title:       labels.CheckTitle(rr.CheckID),
			Description: labels.CheckDescription(rr.CheckID),
		}

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

		r.Summary.Total++
		cat.Checks = append(cat.Checks, cr)
	}

	for _, cat := range sections {
		r.Categories = append(r.Categories, *cat)
	}
	slices.SortFunc(r.Categories, func(a, b CategoryReport) int {
		return checker.CompareCheckIDs(a.ID, b.ID)
	})

	return r
}
