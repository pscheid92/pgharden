package connection

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
)

// Connect establishes a single persistent connection to PostgreSQL.
func Connect(ctx context.Context, connStr string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}

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

// ConnWrapper wraps pgx.Conn to implement checker.DBQuerier.
type ConnWrapper struct {
	Conn *pgx.Conn
}

func (w *ConnWrapper) QueryRow(ctx context.Context, sql string, args ...any) checker.Row {
	return w.Conn.QueryRow(ctx, sql, args...)
}

func (w *ConnWrapper) Query(ctx context.Context, sql string, args ...any) (checker.Rows, error) {
	rows, err := w.Conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &rowsWrapper{rows}, nil
}

type rowsWrapper struct {
	pgx.Rows
}

func (r *rowsWrapper) Close() {
	r.Rows.Close()
}
