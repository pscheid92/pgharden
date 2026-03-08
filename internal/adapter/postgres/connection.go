package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func Connect(ctx context.Context, connStr string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}

	// Use simple protocol (like psql) — pgharden doesn't need prepared statements,
	// and the extended protocol can cause connection reset issues with some proxies
	// (e.g., CNPG controller/manager, kubectl port-forward).
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("pinging PostgreSQL: %w", err)
	}

	return conn, nil
}
