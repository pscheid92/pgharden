package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/pgharden/pgharden/internal/buildinfo"
	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/config"
	"github.com/pgharden/pgharden/internal/connection"
	"github.com/pgharden/pgharden/internal/environment"
	"github.com/pgharden/pgharden/internal/report"
)

// runToWriter runs the full scan and writes the report to w. Used by tests.
func runToWriter(ctx context.Context, cfg *config.Config, opts *RunOptions, w io.Writer) (int, error) {
	conn, env, err := connect(ctx, cfg)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close(ctx) }()

	rpt := runChecks(ctx, cfg, env)

	resolveFormat(cfg, opts)
	if err := writeReportTo(w, cfg.Format, rpt, false); err != nil {
		return 0, err
	}

	return exitCodeFromReport(rpt), nil
}

func run(ctx context.Context, cfg *config.Config, opts *RunOptions) (int, error) {
	conn, env, err := connect(ctx, cfg)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close(ctx) }()

	rpt := runChecks(ctx, cfg, env)

	if err := writeReport(cfg, opts, rpt); err != nil {
		return 0, err
	}

	return exitCodeFromReport(rpt), nil
}

func connect(ctx context.Context, cfg *config.Config) (*connection.Conn, *checker.Environment, error) {
	fmt.Fprintf(os.Stderr, "Connecting to %s:%d as %s...\n", cfg.Host, cfg.Port, cfg.User)
	conn, err := connection.Connect(ctx, cfg.ConnString())
	if err != nil {
		return nil, nil, fmt.Errorf("connection failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Detecting environment...")
	env, err := environment.Detect(ctx, conn)
	if err != nil {
		_ = conn.Close(ctx)
		return nil, nil, fmt.Errorf("environment detection failed: %w", err)
	}
	env.AllowDatabases = cfg.AllowDatabases
	env.ExcludeDatabases = cfg.ExcludeDatabases

	fmt.Fprintf(os.Stderr, "PostgreSQL %d (%s)\n", env.PGVersion, env.PGVersionFull)
	fmt.Fprintf(os.Stderr, "Superuser: %v | Filesystem: %v | Container: %v\n",
		env.IsSuperuser, env.HasFilesystem, env.IsContainer)

	return conn, env, nil
}

func runChecks(ctx context.Context, cfg *config.Config, env *checker.Environment) *report.Report {
	checks := loadChecks()
	runner := &checker.Runner{
		Checks:         checks,
		Env:            env,
		IncludeChecks:  cfg.IncludeChecks,
		ExcludeChecks:  cfg.ExcludeChecks,
		IncludeSection: cfg.IncludeSection,
	}

	fmt.Fprintf(os.Stderr, "Running %d checks...\n", len(checks))
	results := runner.RunAll(ctx)

	meta := report.Metadata{
		Host:        cfg.Host,
		Port:        cfg.Port,
		Database:    cfg.Database,
		ToolVersion: buildinfo.Version,
	}
	return report.Build(results, env, meta, cfg.Lang)
}

