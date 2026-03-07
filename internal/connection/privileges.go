package connection

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Privileges holds the detected privilege level of the connected user.
type Privileges struct {
	IsSuperuser    bool
	IsRDSSuperuser bool
	IsPGMonitor    bool
}

// DetectPrivileges probes the connected user's privilege level.
func DetectPrivileges(ctx context.Context, conn *pgx.Conn) (*Privileges, error) {
	p := &Privileges{}

	// Check superuser — direct attribute, no inheritance needed.
	err := conn.QueryRow(ctx,
		"SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&p.IsSuperuser)
	if err != nil {
		return nil, err
	}

	// Check rds_superuser membership (recursive via pg_has_role).
	// The role may not exist (non-RDS environments), so we check existence first.
	var rdsCount int
	err = conn.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_roles
		WHERE rolname = 'rds_superuser'
		AND pg_has_role(current_user, oid, 'member')`).Scan(&rdsCount)
	if err == nil && rdsCount > 0 {
		p.IsRDSSuperuser = true
	}

	// Check pg_monitor membership (recursive via pg_has_role).
	var monCount int
	err = conn.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_roles
		WHERE rolname = 'pg_monitor'
		AND pg_has_role(current_user, oid, 'member')`).Scan(&monCount)
	if err == nil && monCount > 0 {
		p.IsPGMonitor = true
	}

	return p, nil
}
