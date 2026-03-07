package hba

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pgharden/pgharden/internal/checker"
)

func LoadFromFile(fsys fs.FS, path string) ([]Entry, error) {
	return parseFile(fsys, path, 0)
}

const maxIncludeDepth = 10

func parseFile(fsys fs.FS, path string, depth int) ([]Entry, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("include depth exceeded")
	}

	f, err := fsys.Open(checker.FSPath(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []Entry
	lineNum := 0
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if sub, handled, err := parseInclude(fsys, line, path, depth); handled {
			if err != nil {
				return nil, err
			}
			entries = append(entries, sub...)
			continue
		}

		if entry, ok := parseLine(line, lineNum); ok {
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

func parseInclude(fsys fs.FS, line, parentPath string, depth int) ([]Entry, bool, error) {
	if after, ok := strings.CutPrefix(line, "include_dir "); ok {
		entries, _ := parseIncludeDir(fsys, strings.TrimSpace(after), parentPath, depth)
		return entries, true, nil
	}

	if after, ok := strings.CutPrefix(line, "include_if_exists "); ok {
		incPath := resolveIncludePath(strings.TrimSpace(after), parentPath)
		sub, _ := parseFile(fsys, incPath, depth+1)
		return sub, true, nil
	}

	if after, ok := strings.CutPrefix(line, "include "); ok {
		incPath := resolveIncludePath(strings.TrimSpace(after), parentPath)
		sub, err := parseFile(fsys, incPath, depth+1)
		if err != nil {
			return nil, true, fmt.Errorf("include %s: %w", incPath, err)
		}
		return sub, true, nil
	}

	return nil, false, nil
}

func parseIncludeDir(fsys fs.FS, dir, parentPath string, depth int) ([]Entry, error) {
	dir = resolveIncludePath(dir, parentPath)

	dirEntries, err := fs.ReadDir(fsys, checker.FSPath(dir))
	if err != nil {
		return nil, err
	}

	var entries []Entry
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".conf") {
			continue
		}
		sub, err := parseFile(fsys, filepath.Join(dir, de.Name()), depth+1)
		if err == nil {
			entries = append(entries, sub...)
		}
	}
	return entries, nil
}

func parseLine(line string, lineNum int) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Entry{}, false
	}

	e := Entry{
		LineNumber: lineNum,
		Type:       fields[0],
		Database:   fields[1],
		User:       fields[2],
	}
	rest := fields[3:]

	if e.Type == "local" {
		e.Method = rest[0]
		rest = rest[1:]
	} else {
		e.Address = rest[0]
		rest = rest[1:]

		// If the next field isn't an auth method, it's a netmask.
		if len(rest) > 0 && !authMethods[rest[0]] {
			e.Netmask = rest[0]
			rest = rest[1:]
		}
		if len(rest) > 0 {
			e.Method = rest[0]
			rest = rest[1:]
		}
	}

	if len(rest) > 0 {
		e.Options = strings.Join(rest, " ")
	}

	return e, true
}

var authMethods = map[string]bool{
	"trust": true, "reject": true, "scram-sha-256": true, "md5": true,
	"password": true, "gss": true, "sspi": true, "ident": true,
	"peer": true, "pam": true, "ldap": true, "radius": true, "cert": true,
}

func resolveIncludePath(incPath, parentPath string) string {
	if filepath.IsAbs(incPath) {
		return incPath
	}
	return filepath.Join(filepath.Dir(parentPath), incPath)
}

// LoadFromSQL loads HBA entries from pg_hba_file_rules (PG 15+).
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
