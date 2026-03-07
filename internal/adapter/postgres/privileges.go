package postgres

import (
	"context"

	"github.com/pgharden/pgharden/internal/domain"
)

type Privileges struct {
	IsSuperuser    bool
	IsRDSSuperuser bool
	IsPGMonitor    bool
}

func DetectPrivileges(ctx context.Context, db domain.DBQuerier) (*Privileges, error) {
	p := &Privileges{}

	// Check superuser: direct attribute, no inheritance needed.
	err := db.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&p.IsSuperuser)
	if err != nil {
		return nil, err
	}

	// Check rds_superuser membership (recursive via pg_has_role).
	// The role may not exist (non-RDS environments), so we check existence first.
	var rdsCount int
	err = db.QueryRow(ctx, "SELECT COUNT(*) FROM pg_roles WHERE rolname = 'rds_superuser' AND pg_has_role(current_user, oid, 'member')").Scan(&rdsCount)
	if err == nil && rdsCount > 0 {
		p.IsRDSSuperuser = true
	}

	// Check pg_monitor membership (recursive via pg_has_role).
	var monCount int
	err = db.QueryRow(ctx, "SELECT COUNT(*) FROM pg_roles WHERE rolname = 'pg_monitor' AND pg_has_role(current_user, oid, 'member')").Scan(&monCount)
	if err == nil && monCount > 0 {
		p.IsPGMonitor = true
	}

	return p, nil
}
