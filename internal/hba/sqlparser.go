package hba

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
)

func LoadFromSQL(ctx context.Context, db checker.DBQuerier) ([]Entry, error) {
	rows, err := db.Query(ctx, sqlGetHBA)
	if err != nil {
		return nil, fmt.Errorf("querying pg_hba_file_rules: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Entry])
}

const sqlGetHBA = `
	SELECT
		line_number, type,
		ARRAY_TO_STRING(database, ','),
		ARRAY_TO_STRING(user_name, ','),
		COALESCE(address, ''),
		COALESCE(netmask, ''),
		auth_method,
		COALESCE(ARRAY_TO_STRING(options, ','), '')
	FROM pg_hba_file_rules
	WHERE error IS NULL
	ORDER BY line_number
`
