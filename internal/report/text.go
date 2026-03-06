package report

import (
	"fmt"
	"io"
	"strings"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// WriteText renders the report as human-readable plain text.
func WriteText(w io.Writer, r *Report, color bool) error {
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

	for _, cat := range r.Categories {
		if color {
			fmt.Fprintf(w, "\n%s=== %s: %s ===%s\n", c.bold, cat.ID, cat.Title, c.reset)
		} else {
			fmt.Fprintf(w, "\n=== %s: %s ===\n", cat.ID, cat.Title)
		}

		for _, check := range cat.Checks {
			prefix, prefixColor := statusPrefix(check.Status, c)
			title := check.Title
			if title == "" {
				title = check.ID
			}

			fmt.Fprintf(w, "  %s%-8s%s %s  %s\n", prefixColor, prefix, c.reset, check.ID, title)

			for _, msg := range check.Messages {
				msgColor := messageLevelColor(msg.Level, c)
				fmt.Fprintf(w, "           %s%s%s\n", msgColor, msg.Content, c.reset)
			}

			if check.SkipReason != "" {
				fmt.Fprintf(w, "           %s%s%s\n", c.gray, check.SkipReason, c.reset)
			}
		}
	}

	// Summary
	fmt.Fprintf(w, "\n%s--- Summary ---%s\n", c.bold, c.reset)
	fmt.Fprintf(w, "%s%d passed%s, %s%d failed%s, %s%d skipped%s, %d manual (%d total)\n",
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
		fmt.Fprintf(w, "Failures by severity: %s\n", strings.Join(parts, ", "))
	}

	return nil
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
