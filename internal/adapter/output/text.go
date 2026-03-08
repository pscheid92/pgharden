package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/pscheid92/pgharden/internal/app/report"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func WriteText(w io.Writer, r *report.Report, color bool) error {
	c := &textColors{}
	if color {
		c = &textColors{
			reset:  colorReset,
			red:    colorRed,
			green:  colorGreen,
			yellow: colorYellow,
			gray:   colorGray,
			bold:   colorBold,
		}
	}

	tw := &textWriter{w: w}

	m := r.Metadata
	tw.printf("%spgharden — Security Assessment%s\n", c.bold, c.reset)
	tw.printf("  %sServer%s      %s:%d\n", c.gray, c.reset, m.Host, m.Port)
	tw.printf("  %sDatabase%s    %s\n", c.gray, c.reset, m.Database)
	tw.printf("  %sPostgreSQL%s  %s\n", c.gray, c.reset, m.PGVersion)
	tw.printf("  %sPlatform%s    %s\n", c.gray, c.reset, m.Platform)
	su := "no"
	if m.IsSuperuser {
		su = "yes"
	}
	fs := "no"
	if m.HasFilesystem {
		fs = "yes"
	}
	tw.printf("  %sSuperuser%s   %s\n", c.gray, c.reset, su)
	tw.printf("  %sFilesystem%s  %s\n", c.gray, c.reset, fs)

	for _, cat := range r.Categories {
		if color {
			tw.printf("\n%s=== %s: %s ===%s\n", c.bold, cat.ID, cat.Title, c.reset)
		} else {
			tw.printf("\n=== %s: %s ===\n", cat.ID, cat.Title)
		}

		for _, check := range cat.Checks {
			prefix, prefixColor := statusPrefix(check.Status, c)
			title := check.Title
			if title == "" {
				title = check.ID
			}

			tw.printf("  %s%-8s%s %s  %s\n", prefixColor, prefix, c.reset, check.ID, title)

			if check.Reference != nil {
				tw.printf("           %sSource: %s [%s]%s\n", c.gray, check.Reference.Source, check.Reference.ID, c.reset)
			}

			for _, msg := range check.Messages {
				msgColor := messageLevelColor(msg.Level, c)
				tw.printf("           %s%s%s\n", msgColor, msg.Content, c.reset)
			}

			if check.SkipReason != "" {
				tw.printf("           %s%s%s\n", c.gray, check.SkipReason, c.reset)
			}
		}
	}

	tw.printf("\n%s--- Summary ---%s\n", c.bold, c.reset)
	tw.printf("%s%d passed%s, %s%d failed%s, %s%d skipped%s, %d manual (%d total)\n",
		c.green, r.Summary.Passed, c.reset,
		failColor(r.Summary.Failed, c), r.Summary.Failed, c.reset,
		c.gray, r.Summary.Skipped, c.reset,
		r.Summary.Manual, r.Summary.Total,
	)

	if len(r.Summary.BySeverity) > 0 {
		var parts []string
		for sev, count := range r.Summary.BySeverity {
			parts = append(parts, fmt.Sprintf("%d %s", count, strings.ToLower(sev)))
		}
		tw.printf("Failures by severity: %s\n", strings.Join(parts, ", "))
	}

	return tw.err
}

type textWriter struct {
	w   io.Writer
	err error
}

func (tw *textWriter) printf(format string, args ...any) {
	if tw.err != nil {
		return
	}
	_, tw.err = fmt.Fprintf(tw.w, format, args...)
}

type textColors struct {
	reset, red, green, yellow, gray, bold string
}

func statusPrefix(status string, c *textColors) (string, string) {
	switch status {
	case "PASS":
		return "[PASS]", c.green
	case "FAIL":
		return "[FAIL]", c.red
	case "SKIPPED":
		return "[SKIP]", c.gray
	case "MANUAL":
		return "[MANUAL]", c.yellow
	case "ERROR":
		return "[ERROR]", c.red
	default:
		return "[" + status + "]", ""
	}
}

func messageLevelColor(level string, c *textColors) string {
	switch level {
	case "CRITICAL", "FAILURE":
		return c.red
	case "WARNING":
		return c.yellow
	case "SUCCESS":
		return c.green
	case "INFO":
		return c.gray
	default:
		return ""
	}
}

func failColor(count int, c *textColors) string {
	if count > 0 {
		return c.red
	}
	return ""
}
