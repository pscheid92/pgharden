package cli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/pgharden/pgharden/internal/adapter/environment"
	"github.com/pgharden/pgharden/internal/adapter/postgres"
	"github.com/pgharden/pgharden/internal/app/report"
	"github.com/pgharden/pgharden/internal/app/scanner"
	"github.com/pgharden/pgharden/internal/domain"
	"github.com/pgharden/pgharden/internal/platform/buildinfo"
	"github.com/pgharden/pgharden/internal/platform/config"
)

// Connector abstracts the database connection. Production code uses dbConnector;
// tests inject a mock.
type Connector interface {
	Connect(ctx context.Context, cfg *config.Config) (db domain.DBQuerier, close func(), err error)
}

// Detector abstracts environment detection. Production code uses envDetector
// (SQL queries); tests inject a mock returning a pre-built Environment.
type Detector interface {
	Detect(ctx context.Context, db domain.DBQuerier) (*domain.Environment, error)
}

// ReportWriter abstracts report output. Production uses cliReportWriter
// (file/stdout with color detection); tests inject a bufferWriter.
type ReportWriter interface {
	WriteReport(rpt *report.Report) error
}

type dbConnector struct{}

func (c *dbConnector) Connect(ctx context.Context, cfg *config.Config) (domain.DBQuerier, func(), error) {
	slog.Info("connecting", "host", cfg.Host, "port", cfg.Port, "user", cfg.User)
	conn, err := postgres.Connect(ctx, cfg.ConnString())
	if err != nil {
		return nil, nil, fmt.Errorf("connection failed: %w", err)
	}
	closer := func() { _ = conn.Close(ctx) }
	return conn, closer, nil
}

type envDetector struct{}

func (d *envDetector) Detect(ctx context.Context, db domain.DBQuerier) (*domain.Environment, error) {
	return environment.Detect(ctx, db)
}

func run(ctx context.Context, connector Connector, detector Detector, cfg *config.Config, writer ReportWriter) (int, error) {
	db, closer, err := connector.Connect(ctx, cfg)
	if err != nil {
		return 0, err
	}
	defer closer()

	env, err := detectEnv(ctx, detector, db, cfg)
	if err != nil {
		return 0, err
	}

	result := scanner.Scan(ctx, env, scanOpts(cfg))

	if err := writer.WriteReport(result.Report); err != nil {
		return 0, err
	}

	return result.ExitCode, nil
}

func detectEnv(ctx context.Context, detector Detector, db domain.DBQuerier, cfg *config.Config) (*domain.Environment, error) {
	slog.Info("detecting environment")
	env, err := detector.Detect(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("environment detection failed: %w", err)
	}
	env.AllowDatabases = cfg.AllowDatabases
	env.ExcludeDatabases = cfg.ExcludeDatabases
	if cfg.Platform != "" {
		env.Platform = cfg.Platform
	}
	if cfg.Local {
		environment.EnableLocal(env)
	}

	slog.Info("connected",
		"pg_version", env.PGVersion,
		"pg_version_full", env.PGVersionFull,
		"superuser", env.IsSuperuser,
		"filesystem", env.HasFilesystem,
		"platform", env.Platform,
	)
	return env, nil
}

func scanOpts(cfg *config.Config) scanner.Options {
	return scanner.Options{
		IncludeChecks:  cfg.IncludeChecks,
		ExcludeChecks:  cfg.ExcludeChecks,
		IncludeSection: cfg.IncludeSection,
		Meta: report.Metadata{
			Host:        cfg.Host,
			Port:        cfg.Port,
			Database:    cfg.Database,
			ToolVersion: buildinfo.Version,
		},
	}
}
