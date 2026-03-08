package cli

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/pscheid92/pgharden/internal/adapter/output"
	"github.com/pscheid92/pgharden/internal/app/report"
	"github.com/pscheid92/pgharden/internal/platform/config"
)

type cliReportWriter struct {
	cfg  *config.Config
	opts *RunOptions
}

func (w *cliReportWriter) WriteReport(rpt *report.Report) error {
	return writeReport(w.cfg, w.opts, rpt)
}

func writeReport(cfg *config.Config, opts *RunOptions, rpt *report.Report) error {
	resolveFormat(cfg, opts)

	out, closer, err := openOutput(cfg.Output)
	if err != nil {
		return err
	}
	defer closer()

	useColor := cfg.Format == "text" && !opts.NoColor && os.Getenv("NO_COLOR") == "" && cfg.Output == "" && isTerminal(os.Stdout)
	return writeReportTo(out, cfg.Format, rpt, useColor)
}

func writeReportTo(w io.Writer, format string, rpt *report.Report, color bool) error {
	switch format {
	case "text":
		return output.WriteText(w, rpt, color)
	case "json":
		return output.WriteJSON(w, rpt)
	case "html":
		return output.WriteHTML(w, rpt)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func resolveFormat(cfg *config.Config, opts *RunOptions) {
	if opts.FormatExplicit {
		return
	}
	if cfg.Output != "" {
		cfg.Format = "json"
	} else if isTerminal(os.Stdout) {
		cfg.Format = "text"
	}
}

func openOutput(path string) (*os.File, func(), error) {
	closer := func() { /* EMPTY */ }

	if path == "" {
		return os.Stdout, closer, nil
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, closer, fmt.Errorf("creating output file: %w", err)
	}

	closer = func() { _ = f.Close() }
	return f, closer, nil
}

var isTerminal = func(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
