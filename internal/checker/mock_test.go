package checker

import (
	"context"
	"fmt"
)

// mockDB implements DBQuerier for tests.
type mockDB struct {
	// rows maps a SQL prefix to a list of row results.
	rows map[string][]map[string]any
	// scalars maps a SQL prefix to a single scalar value.
	scalars map[string]any
	// errors maps a SQL prefix to an error.
	errors map[string]error
}

func newMockDB() *mockDB {
	return &mockDB{
		rows:    make(map[string][]map[string]any),
		scalars: make(map[string]any),
		errors:  make(map[string]error),
	}
}

func (m *mockDB) QueryRow(_ context.Context, sql string, _ ...any) Row {
	for prefix, err := range m.errors {
		if len(sql) >= len(prefix) && sql[:len(prefix)] == prefix {
			return &mockRow{err: err}
		}
	}
	for prefix, val := range m.scalars {
		if len(sql) >= len(prefix) && sql[:len(prefix)] == prefix {
			return &mockRow{val: val}
		}
	}
	return &mockRow{err: fmt.Errorf("no mock for query: %s", sql)}
}

func (m *mockDB) Query(_ context.Context, sql string, _ ...any) (Rows, error) {
	for prefix, err := range m.errors {
		if len(sql) >= len(prefix) && sql[:len(prefix)] == prefix {
			return nil, err
		}
	}
	for prefix, rows := range m.rows {
		if len(sql) >= len(prefix) && sql[:len(prefix)] == prefix {
			return &mockRows{data: rows}, nil
		}
	}
	return nil, fmt.Errorf("no mock for query: %s", sql)
}

// mockRow implements Row.
type mockRow struct {
	val any
	err error
}

func (r *mockRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) > 0 {
		switch d := dest[0].(type) {
		case *string:
			*d = fmt.Sprintf("%v", r.val)
		case *int:
			if v, ok := r.val.(int); ok {
				*d = v
			}
		case *bool:
			if v, ok := r.val.(bool); ok {
				*d = v
			}
		}
	}
	return nil
}

// mockRows implements Rows.
type mockRows struct {
	data []map[string]any
	idx  int
}

func (r *mockRows) Next() bool {
	return r.idx < len(r.data)
}

func (r *mockRows) Scan(dest ...any) error {
	if r.idx >= len(r.data) {
		return fmt.Errorf("no more rows")
	}
	row := r.data[r.idx]
	r.idx++
	i := 0
	for _, v := range row {
		if i < len(dest) {
			switch d := dest[i].(type) {
			case *string:
				*d = fmt.Sprintf("%v", v)
			case *int:
				if val, ok := v.(int); ok {
					*d = val
				}
			case *bool:
				if val, ok := v.(bool); ok {
					*d = val
				}
			}
		}
		i++
	}
	return nil
}

func (r *mockRows) Close() {}

func (r *mockRows) Err() error { return nil }
