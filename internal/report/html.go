package report

import (
	"embed"
	"html/template"
	"io"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

// WriteHTML renders the report as self-contained HTML.
func WriteHTML(w io.Writer, r *Report) error {
	funcMap := template.FuncMap{
		"statusClass": func(status string) string {
			switch status {
			case "PASS":
				return "success"
			case "FAIL":
				return "danger"
			case "SKIPPED":
				return "secondary"
			case "MANUAL":
				return "info"
			default:
				return "warning"
			}
		},
		"statusIcon": func(status string) template.HTML {
			// Inline SVGs for pixel-perfect rendering across all platforms.
			const sz = `width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"`
			switch status {
			case "PASS":
				// Checkmark
				return template.HTML(`<svg ` + sz + `><polyline points="4 12 10 18 20 6"/></svg>`)
			case "FAIL":
				// X
				return template.HTML(`<svg ` + sz + `><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>`)
			case "SKIPPED":
				// Dash
				return template.HTML(`<svg ` + sz + `><line x1="5" y1="12" x2="19" y2="12"/></svg>`)
			case "MANUAL":
				// Eye
				return template.HTML(`<svg ` + sz + ` stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`)
			default:
				return "?"
			}
		},
		"severityClass": func(severity string) string {
			switch severity {
			case "CRITICAL":
				return "danger"
			case "WARNING":
				return "warning"
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
	}

	tmpl, err := template.New("report.html.tmpl").Funcs(funcMap).ParseFS(templateFS, "templates/report.html.tmpl")
	if err != nil {
		return err
	}

	return tmpl.Execute(w, r)
}
