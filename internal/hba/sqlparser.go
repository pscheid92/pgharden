package hba

import (
	"context"
	"fmt"

	"github.com/pgharden/pgharden/internal/checker"
)

// LoadFromSQL loads HBA entries from pg_hba_file_rules (PG 15+).
func LoadFromSQL(ctx context.Context, db checker.DBQuerier) ([]Entry, error) {
	rows, err := db.Query(ctx, `
		SELECT line_number, type, ARRAY_TO_STRING(database, ','),
		       ARRAY_TO_STRING(user_name, ','), address, netmask,
		       auth_method, COALESCE(ARRAY_TO_STRING(options, ','), '')
		FROM pg_hba_file_rules
		WHERE error IS NULL
		ORDER BY line_number`)
	if err != nil {
		return nil, fmt.Errorf("querying pg_hba_file_rules: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var address, netmask *string
		if err := rows.Scan(&e.LineNumber, &e.Type, &e.Database, &e.User,
			&address, &netmask, &e.Method, &e.Options); err != nil {
			return nil, fmt.Errorf("scanning HBA row: %w", err)
		}
		if address != nil {
			e.Address = *address
		}
		if netmask != nil {
			e.Netmask = *netmask
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
