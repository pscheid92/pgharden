package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/config"
	"github.com/pgharden/pgharden/internal/connection"
	"github.com/pgharden/pgharden/internal/environment"
	"github.com/pgharden/pgharden/internal/report"

	// Import check packages for self-registration.
	_ "github.com/pgharden/pgharden/internal/checks/section1"
	_ "github.com/pgharden/pgharden/internal/checks/section2"
	_ "github.com/pgharden/pgharden/internal/checks/section3"
	_ "github.com/pgharden/pgharden/internal/checks/section4"
	_ "github.com/pgharden/pgharden/internal/checks/section5"
	_ "github.com/pgharden/pgharden/internal/checks/section6"
	_ "github.com/pgharden/pgharden/internal/checks/section7"
	_ "github.com/pgharden/pgharden/internal/checks/section8"

	// Import labels.
	_ "github.com/pgharden/pgharden/internal/labels"
)

var version = "dev"

func main() {
	cfg := config.DefaultConfig()

	var exitCode int
	var noColor bool
	var formatExplicit bool

	rootCmd := &cobra.Command{
		Use:   "pgharden",
		Short: "PostgreSQL Database Security Assessment Tool",
		Long:  "Automated security assessment of PostgreSQL databases following CIS Benchmark recommendations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			formatExplicit = cmd.Flags().Changed("format")
			var err error
			exitCode, err = run(cmd.Context(), cfg, formatExplicit, noColor)
			return err
		},
		SilenceUsage: true,
	}

	flags := rootCmd.Flags()
	flags.StringVarP(&cfg.Host, "host", "H", cfg.Host, "PostgreSQL server host")
	flags.IntVarP(&cfg.Port, "port", "p", cfg.Port, "PostgreSQL server port")
	flags.StringVarP(&cfg.User, "user", "U", cfg.User, "PostgreSQL user")
	flags.StringVarP(&cfg.Database, "database", "d", cfg.Database, "Database to connect to")
	flags.StringVar(&cfg.DSN, "dsn", "", "Full connection string (overrides host/port/user/database)")
	flags.StringVarP(&cfg.Format, "format", "f", cfg.Format, "Output format: text, json, html")
	flags.BoolVar(&noColor, "no-color", false, "Disable colored output")
	flags.StringVarP(&cfg.Output, "output", "o", cfg.Output, "Output file (default: stdout)")
	flags.StringVarP(&cfg.Lang, "lang", "l", cfg.Lang, "Language: en_US, fr_FR, zh_CN")
	flags.StringVar(&cfg.Title, "title", "", "Report title")
	flags.StringSliceVar(&cfg.IncludeChecks, "include", nil, "Only run these check IDs")
	flags.StringSliceVar(&cfg.ExcludeChecks, "exclude", nil, "Skip these check IDs")
	flags.StringVar(&cfg.IncludeSection, "section", "", "Only run checks in this section")
	flags.StringSliceVarP(&cfg.AllowDatabases, "allow", "a", nil, "Only check these databases")
	flags.StringSliceVarP(&cfg.ExcludeDatabases, "exclude-db", "e", nil, "Exclude these databases")
	flags.StringVar(&cfg.Profile, "profile", "", "Configuration profile to use")

	var configFile string
	flags.StringVarP(&configFile, "config", "c", "", "Path to YAML config file")

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if configFile != "" {
			return cfg.LoadFile(configFile)
		}
		return nil
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("pgharden %s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(3)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run(ctx context.Context, cfg *config.Config, formatExplicit bool, noColor bool) (int, error) {
	// Connect
	fmt.Fprintf(os.Stderr, "Connecting to %s:%d as %s...\n", cfg.Host, cfg.Port, cfg.User)
	conn, err := connection.Connect(ctx, cfg.ConnString())
	if err != nil {
		return 0, fmt.Errorf("connection failed: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	db := &connection.ConnWrapper{Conn: conn}

	// Detect environment
	fmt.Fprintln(os.Stderr, "Detecting environment...")
	env, err := environment.Detect(ctx, conn, db)
	if err != nil {
		return 0, fmt.Errorf("environment detection failed: %w", err)
	}
	env.AllowDatabases = cfg.AllowDatabases
	env.ExcludeDatabases = cfg.ExcludeDatabases

	fmt.Fprintf(os.Stderr, "PostgreSQL %d (%s)\n", env.PGVersion, env.PGVersionFull)
	fmt.Fprintf(os.Stderr, "Superuser: %v | Filesystem: %v | Container: %v\n",
		env.IsSuperuser, env.HasFilesystem, env.IsContainer)

	// Run checks
	runner := &checker.Runner{
		Env:            env,
		IncludeChecks:  cfg.IncludeChecks,
		ExcludeChecks:  cfg.ExcludeChecks,
		IncludeSection: cfg.IncludeSection,
	}

	fmt.Fprintf(os.Stderr, "Running %d checks...\n", len(checker.All()))
	results := runner.RunAll(ctx)

	// Build report
	meta := report.Metadata{
		Host:        cfg.Host,
		Port:        cfg.Port,
		Database:    cfg.Database,
		ToolVersion: version,
	}
	rpt := report.Build(results, env, meta, cfg.Lang)

	// Smart default format: text for TTY stdout, json for file output
	if !formatExplicit {
		if cfg.Output != "" {
			cfg.Format = "json"
		} else if isTerminal(os.Stdout) {
			cfg.Format = "text"
		}
	}

	// Color detection
	useColor := cfg.Format == "text" && !noColor && os.Getenv("NO_COLOR") == "" && cfg.Output == "" && isTerminal(os.Stdout)

	// Output
	var out *os.File
	if cfg.Output != "" {
		out, err = os.Create(cfg.Output)
		if err != nil {
			return 0, fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = out.Close() }()
	} else {
		out = os.Stdout
	}

	switch cfg.Format {
	case "text":
		if err := report.WriteText(out, rpt, useColor); err != nil {
			return 0, fmt.Errorf("writing text report: %w", err)
		}
	case "json":
		if err := report.WriteJSON(out, rpt); err != nil {
			return 0, fmt.Errorf("writing JSON report: %w", err)
		}
	case "html":
		if err := report.WriteHTML(out, rpt); err != nil {
			return 0, fmt.Errorf("writing HTML report: %w", err)
		}
	default:
		return 0, fmt.Errorf("unsupported format: %s", cfg.Format)
	}

	// Exit code based on results
	if rpt.Summary.BySeverity["CRITICAL"] > 0 {
		return 1, nil
	}
	if rpt.Summary.Failed > 0 {
		return 2, nil
	}

	return 0, nil
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}
