package connection

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
)

// Conn wraps a PostgreSQL connection, hiding the pgx dependency from callers.
type Conn struct {
	pgx *pgx.Conn
	DB  checker.DBQuerier
}

// Close closes the underlying connection.
func (c *Conn) Close(ctx context.Context) error {
	return c.pgx.Close(ctx)
}

// Connect establishes a single persistent connection to PostgreSQL.
func Connect(ctx context.Context, connStr string) (*Conn, error) {
	cfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}

	pgConn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}

	if err := pgConn.Ping(ctx); err != nil {
		_ = pgConn.Close(ctx)
		return nil, fmt.Errorf("pinging PostgreSQL: %w", err)
	}

	wrapper := &connWrapper{pgConn}
	return &Conn{pgx: pgConn, DB: wrapper}, nil
}

// DetectPrivileges probes the connected user's privilege level.
func (c *Conn) DetectPrivileges(ctx context.Context) (*Privileges, error) {
	return detectPrivileges(ctx, c.pgx)
}

// QueryRow executes a query returning a single row (used by environment detection).
func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) checker.Row {
	return c.pgx.QueryRow(ctx, sql, args...)
}

// Query executes a query returning multiple rows (used by environment detection).
func (c *Conn) Query(ctx context.Context, sql string, args ...any) (checker.Rows, error) {
	rows, err := c.pgx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &rowsWrapper{rows}, nil
}

// connWrapper implements checker.DBQuerier.
type connWrapper struct {
	conn *pgx.Conn
}

func (w *connWrapper) QueryRow(ctx context.Context, sql string, args ...any) checker.Row {
	return w.conn.QueryRow(ctx, sql, args...)
}

func (w *connWrapper) Query(ctx context.Context, sql string, args ...any) (checker.Rows, error) {
	rows, err := w.conn.Query(ctx, sql, args...)
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
