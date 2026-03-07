package cli

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/pgharden/pgharden/internal/config"
)

// RunOptions holds CLI-only flags that don't belong in config.
type RunOptions struct {
	NoColor        bool
	FormatExplicit bool
}

// Execute sets up and runs the CLI, returning the desired process exit code.
func Execute() (int, error) {
	cfg := config.DefaultConfig()
	opts := &RunOptions{}

	var exitCode int
	var configFile string

	rootCmd := &cobra.Command{
		Use:   "pgharden",
		Short: "PostgreSQL Database Security Assessment Tool",
		Long:  "Automated security assessment of PostgreSQL databases following CIS Benchmark recommendations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.FormatExplicit = cmd.Flags().Changed("format")
			var err error
			exitCode, err = run(cmd.Context(), cfg, opts)
			return err
		},
		SilenceUsage: true,
	}

	registerFlags(rootCmd, cfg, opts, &configFile)
	rootCmd.AddCommand(versionCmd())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return exitCode, rootCmd.ExecuteContext(ctx)
}

func registerFlags(cmd *cobra.Command, cfg *config.Config, opts *RunOptions, configFile *string) {
	f := cmd.Flags()

	// Connection
	f.StringVarP(&cfg.Host, "host", "H", cfg.Host, "PostgreSQL server host")
	f.IntVarP(&cfg.Port, "port", "p", cfg.Port, "PostgreSQL server port")
	f.StringVarP(&cfg.User, "user", "U", cfg.User, "PostgreSQL user")
	f.StringVarP(&cfg.Database, "database", "d", cfg.Database, "Database to connect to")
	f.StringVar(&cfg.DSN, "dsn", "", "Full connection string (overrides host/port/user/database)")

	// Output
	f.StringVarP(&cfg.Format, "format", "f", cfg.Format, "Output format: text, json, html")
	f.StringVarP(&cfg.Output, "output", "o", cfg.Output, "Output file (default: stdout)")
	f.BoolVar(&opts.NoColor, "no-color", false, "Disable colored output")
f.StringVar(&cfg.Title, "title", "", "Report title")

	// Filtering
	f.StringSliceVar(&cfg.IncludeChecks, "include", nil, "Only run these check IDs")
	f.StringSliceVar(&cfg.ExcludeChecks, "exclude", nil, "Skip these check IDs")
	f.StringVar(&cfg.IncludeSection, "section", "", "Only run checks in this section")
	f.StringSliceVarP(&cfg.AllowDatabases, "allow", "a", nil, "Only check these databases")
	f.StringSliceVarP(&cfg.ExcludeDatabases, "exclude-db", "e", nil, "Exclude these databases")

	// Config
	f.StringVar(&cfg.Profile, "profile", "", "Configuration profile to use")
	f.StringVarP(configFile, "config", "c", "", "Path to YAML config file")

	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if *configFile != "" {
			return cfg.LoadFile(*configFile)
		}
		return nil
	}
}
