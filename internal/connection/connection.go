package connection

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Conn wraps a PostgreSQL connection, hiding the pgx dependency from callers.
type Conn struct {
	pgx *pgx.Conn
}

// DB returns the underlying connection as a DBQuerier for use by checks.
func (c *Conn) DB() *pgx.Conn { return c.pgx }

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

	return &Conn{pgx: pgConn}, nil
}

// DetectPrivileges probes the connected user's privilege level.
func (c *Conn) DetectPrivileges(ctx context.Context) (*Privileges, error) {
	return detectPrivileges(ctx, c.pgx)
}

// QueryRow delegates to the underlying pgx connection.
func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return c.pgx.QueryRow(ctx, sql, args...)
}

// Query delegates to the underlying pgx connection.
func (c *Conn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return c.pgx.Query(ctx, sql, args...)
}
