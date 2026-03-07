package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/pgharden/pgharden/internal/config"
	"github.com/pgharden/pgharden/internal/report"
)

func writeReport(cfg *config.Config, opts *RunOptions, rpt *report.Report) error {
	resolveFormat(cfg, opts)
	useColor := cfg.Format == "text" && !opts.NoColor && os.Getenv("NO_COLOR") == "" && cfg.Output == "" && isTerminal(os.Stdout)

	out, closer, err := openOutput(cfg.Output)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	switch cfg.Format {
	case "text":
		return report.WriteText(out, rpt, useColor)
	case "json":
		return report.WriteJSON(out, rpt)
	case "html":
		return report.WriteHTML(out, rpt)
	default:
		return fmt.Errorf("unsupported format: %s", cfg.Format)
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
	if path == "" {
		return os.Stdout, nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating output file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
