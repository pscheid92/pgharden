package hba

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// LoadFromFile parses a pg_hba.conf file (fallback for PG < 15).
func LoadFromFile(path string) ([]Entry, error) {
	return parseFile(path, 0)
}

func parseFile(path string, depth int) ([]Entry, error) {
	if depth > 10 {
		return nil, fmt.Errorf("include depth exceeded")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle include directives
		if after, ok := strings.CutPrefix(line, "include_dir "); ok {
			dir := strings.TrimSpace(after)
			dir = resolveIncludePath(dir, path)
			dirEntries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, de := range dirEntries {
				if de.IsDir() || !strings.HasSuffix(de.Name(), ".conf") {
					continue
				}
				sub, err := parseFile(filepath.Join(dir, de.Name()), depth+1)
				if err == nil {
					entries = append(entries, sub...)
				}
			}
			continue
		}
		if after, ok := strings.CutPrefix(line, "include_if_exists "); ok {
			incPath := strings.TrimSpace(after)
			incPath = resolveIncludePath(incPath, path)
			sub, err := parseFile(incPath, depth+1)
			if err == nil {
				entries = append(entries, sub...)
			}
			continue
		}
		if after, ok := strings.CutPrefix(line, "include "); ok {
			incPath := strings.TrimSpace(after)
			incPath = resolveIncludePath(incPath, path)
			sub, err := parseFile(incPath, depth+1)
			if err != nil {
				return nil, fmt.Errorf("include %s: %w", incPath, err)
			}
			entries = append(entries, sub...)
			continue
		}

		// Parse HBA entry
		entry, ok := parseLine(line, lineNum)
		if ok {
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

func parseLine(line string, lineNum int) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Entry{}, false
	}

	e := Entry{
		LineNumber: lineNum,
		Type:       fields[0],
	}

	idx := 1
	e.Database = fields[idx]
	idx++
	e.User = fields[idx]
	idx++

	if e.Type == "local" {
		// local  database  user  method  [options]
		if idx < len(fields) {
			e.Method = fields[idx]
			idx++
		}
	} else {
		// host/hostssl/etc  database  user  address  method  [options]
		if idx < len(fields) {
			e.Address = fields[idx]
			idx++
		}
		// Check if next field is a netmask (not an auth method)
		if idx < len(fields) && !isAuthMethod(fields[idx]) {
			e.Netmask = fields[idx]
			idx++
		}
		if idx < len(fields) {
			e.Method = fields[idx]
			idx++
		}
	}

	if idx < len(fields) {
		e.Options = strings.Join(fields[idx:], " ")
	}

	return e, true
}

func isAuthMethod(s string) bool {
	methods := []string{"trust", "reject", "scram-sha-256", "md5", "password",
		"gss", "sspi", "ident", "peer", "pam", "ldap", "radius", "cert"}
	return slices.Contains(methods, s)
}

func resolveIncludePath(incPath, parentPath string) string {
	if filepath.IsAbs(incPath) {
		return incPath
	}
	return filepath.Join(filepath.Dir(parentPath), incPath)
}
