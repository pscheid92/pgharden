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

	// Check superuser
	err := conn.QueryRow(ctx,
		"SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&p.IsSuperuser)
	if err != nil {
		return nil, err
	}

	// Check rds_superuser (AWS RDS)
	var rdsCount int
	err = conn.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_roles r
		JOIN pg_auth_members m ON m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
		WHERE r.oid = m.roleid AND r.rolname = 'rds_superuser'`).Scan(&rdsCount)
	if err == nil && rdsCount > 0 {
		p.IsRDSSuperuser = true
	}

	// Check pg_monitor membership
	var monCount int
	err = conn.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_roles r
		JOIN pg_auth_members m ON m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
		WHERE r.oid = m.roleid AND r.rolname = 'pg_monitor'`).Scan(&monCount)
	if err == nil && monCount > 0 {
		p.IsPGMonitor = true
	}

	return p, nil
}
