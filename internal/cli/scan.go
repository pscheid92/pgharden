package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/pgharden/pgharden/internal/buildinfo"
	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/config"
	"github.com/pgharden/pgharden/internal/connection"
	"github.com/pgharden/pgharden/internal/environment"
	"github.com/pgharden/pgharden/internal/report"
)

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

func connect(ctx context.Context, cfg *config.Config) (*pgx.Conn, *checker.Environment, error) {
	slog.Info("connecting", "host", cfg.Host, "port", cfg.Port, "user", cfg.User)
	conn, err := connection.Connect(ctx, cfg.ConnString())
	if err != nil {
		return nil, nil, fmt.Errorf("connection failed: %w", err)
	}

	slog.Info("detecting environment")
	env, err := environment.Detect(ctx, conn)
	if err != nil {
		_ = conn.Close(ctx)
		return nil, nil, fmt.Errorf("environment detection failed: %w", err)
	}
	env.AllowDatabases = cfg.AllowDatabases
	env.ExcludeDatabases = cfg.ExcludeDatabases

	slog.Info("connected",
		"pg_version", env.PGVersion,
		"pg_version_full", env.PGVersionFull,
		"superuser", env.IsSuperuser,
		"filesystem", env.HasFilesystem,
		"container", env.IsContainer,
	)

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

	slog.Info("running checks", "count", len(checks))
	results := runner.RunAll(ctx)

	meta := report.Metadata{
		Host:        cfg.Host,
		Port:        cfg.Port,
		Database:    cfg.Database,
		ToolVersion: buildinfo.Version,
	}
	return report.Build(results, env, meta)
}
