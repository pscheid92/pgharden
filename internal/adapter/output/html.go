package output

import (
	"embed"
	"fmt"
	"html/template"
	"io"

	"github.com/pscheid92/pgharden/internal/app/report"
	"github.com/pscheid92/pgharden/internal/domain"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

func WriteHTML(w io.Writer, r *report.Report) error {
	funcMap := template.FuncMap{
		"statusClass": func(status string) string {
			switch status {
			case "PASS":
				return "pass"
			case "FAIL":
				return "fail"
			case "SKIPPED":
				return "skip"
			case "MANUAL":
				return "manual"
			default:
				return "warn"
			}
		},
		"statusIcon": func(status string) template.HTML {
			const sz = `width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"`
			switch status {
			case "PASS":
				return template.HTML(`<svg ` + sz + `><polyline points="4 12 10 18 20 6"/></svg>`)
			case "FAIL":
				return template.HTML(`<svg ` + sz + `><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>`)
			case "SKIPPED":
				return template.HTML(`<svg ` + sz + `><line x1="5" y1="12" x2="19" y2="12"/></svg>`)
			case "MANUAL":
				return template.HTML(`<svg ` + sz + `><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`)
			default:
				return "?"
			}
		},
		"severityClass": func(severity string) string {
			switch severity {
			case "CRITICAL":
				return "fail"
			case "WARNING":
				return "warn"
			default:
				return "info"
			}
		},
		"hasDetails": func(details [][]string) bool {
			return len(details) > 0
		},
		"isHeader": func(i int) bool {
			return i == 0
		},
		"passPercent": func(s report.Summary) int {
			evaluated := s.Passed + s.Failed
			if evaluated == 0 {
				return 100
			}
			return (s.Passed * 100) / evaluated
		},
		"sectionStats": func(checks []report.CheckReport) template.HTML {
			var pass, fail, skip, manual int
			for _, c := range checks {
				switch c.Status {
				case "PASS":
					pass++
				case "FAIL":
					fail++
				case "SKIPPED":
					skip++
				case "MANUAL":
					manual++
				}
			}
			var s string
			if pass > 0 {
				s += fmt.Sprintf(`<span class="sh-stat sh-pass">%d passed</span>`, pass)
			}
			if fail > 0 {
				s += fmt.Sprintf(`<span class="sh-stat sh-fail">%d failed</span>`, fail)
			}
			if skip > 0 {
				s += fmt.Sprintf(`<span class="sh-stat sh-skip">%d skipped</span>`, skip)
			}
			if manual > 0 {
				s += fmt.Sprintf(`<span class="sh-stat sh-manual">%d manual</span>`, manual)
			}
			return template.HTML(s)
		},
		"refSource": func(ref *domain.Reference) string {
			if ref == nil {
				return ""
			}
			return ref.Source
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
		"sub": func(a, b float64) float64 {
			return a - b
		},
		"toFloat": func(i int) float64 {
			return float64(i)
		},
	}

	tmpl, err := template.New("report.html.tmpl").Funcs(funcMap).ParseFS(templateFS, "templates/report.html.tmpl")
	if err != nil {
		return err
	}

	return tmpl.Execute(w, r)
}
