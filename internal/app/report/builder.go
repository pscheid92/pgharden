package report

import (
	"slices"
	"time"

	"github.com/pscheid92/pgharden/internal/domain"
	"github.com/pscheid92/pgharden/internal/platform/labels"
)

func Build(results []domain.RunResult, env *domain.Environment, meta Metadata) *Report {
	meta.Timestamp = time.Now().UTC()
	if env != nil {
		meta.PGVersion = env.PGVersionFull
		meta.PGVersionMajor = env.PGVersion
		meta.Platform = env.Platform
		meta.IsSuperuser = env.IsSuperuser
		meta.HasFilesystem = env.HasFilesystem
	}

	r := &Report{
		Metadata: meta,
		Summary: Summary{
			BySeverity: make(map[string]int),
		},
	}

	sections := make(map[string]*CategoryReport)

	for _, rr := range results {
		sectionID := domain.SectionID(rr.CheckID)

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
			Reference:   rr.Reference,
		}

		cr.Status = rr.Result.Status.String()
		cr.Severity = rr.Result.Severity.String()
		cr.SkipReason = rr.Result.SkipReason
		cr.Details = rr.Result.Details

		for _, m := range rr.Result.Messages {
			cr.Messages = append(cr.Messages, MsgEntry{Level: m.Level, Content: m.Content})
		}

		switch rr.Result.Status {
		case domain.StatusPass:
			r.Summary.Passed++
		case domain.StatusFail:
			r.Summary.Failed++
			r.Summary.BySeverity[cr.Severity]++
		case domain.StatusSkipped:
			r.Summary.Skipped++
		case domain.StatusManual:
			r.Summary.Manual++
		}

		r.Summary.Total++
		cat.Checks = append(cat.Checks, cr)
	}

	for _, cat := range sections {
		r.Categories = append(r.Categories, *cat)
	}
	slices.SortFunc(r.Categories, func(a, b CategoryReport) int {
		return domain.CompareCheckIDs(a.ID, b.ID)
	})

	return r
}
