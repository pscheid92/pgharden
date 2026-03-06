package section4

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pgharden/pgharden/internal/checker"
)

func init() {
	checker.Register(&check_4_1{})
	checker.Register(&check_4_3{})
	checker.Register(&check_4_4{})
	checker.Register(&check_4_5{})
	checker.Register(&check_4_6{})
	checker.Register(&check_4_7{})
	checker.Register(&check_4_8{})
	checker.Register(&check_4_10{})
}

// --- Check 4.1 ---

type check_4_1 struct{}

func (c *check_4_1) ID() string { return "4.1" }

func (c *check_4_1) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{Filesystem: true}
}

func (c *check_4_1) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	f, err := os.Open("/etc/passwd")
	if err != nil {
		result.Status = checker.StatusSkipped
		result.SkipReason = "Cannot read /etc/passwd: " + err.Error()
		return result, nil
	}
	defer func() { _ = f.Close() }()

	noLoginShells := map[string]bool{
		"/bin/false":        true,
		"/usr/sbin/nologin": true,
		"/sbin/nologin":     true,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		if fields[0] != "postgres" {
			continue
		}

		shell := fields[6]
		if noLoginShells[shell] {
			result.Status = checker.StatusPass
			result.Messages = append(result.Messages, checker.Message{
				Level:   "SUCCESS",
				Content: "postgres user has no interactive shell: " + shell,
			})
		} else {
			result.Status = checker.StatusFail
			result.Messages = append(result.Messages, checker.Message{
				Level:   "FAILURE",
				Content: "postgres user has interactive shell: " + shell + " (expected /bin/false or nologin)",
			})
		}
		return result, nil
	}

	result.Status = checker.StatusSkipped
	result.SkipReason = "postgres user not found in /etc/passwd"
	return result, nil
}

// --- Check 4.3 ---

type check_4_3 struct{}

func (c *check_4_3) ID() string { return "4.3" }

func (c *check_4_3) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_4_3) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY rolname")
	if err != nil {
		return nil, fmt.Errorf("query superusers: %w", err)
	}
	defer rows.Close()

	var superusers []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan superuser: %w", err)
		}
		superusers = append(superusers, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate superusers: %w", err)
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	if len(superusers) <= 1 {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "Only the expected superuser account exists.",
		})
	} else {
		result.Status = checker.StatusFail
		result.Details = [][]string{{"Superuser Role"}}
		for _, su := range superusers {
			result.Details = append(result.Details, []string{su})
		}
		result.Messages = append(result.Messages, checker.Message{
			Level:   "WARNING",
			Content: fmt.Sprintf("Found %d superuser roles; only 'postgres' should have superuser privileges.", len(superusers)),
		})
	}

	return result, nil
}

// --- Check 4.4 ---

type check_4_4 struct{}

func (c *check_4_4) ID() string { return "4.4" }

func (c *check_4_4) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_4_4) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx,
		"SELECT rolname, rolconnlimit FROM pg_roles WHERE rolcanlogin AND NOT rolsuper ORDER BY rolname")
	if err != nil {
		return nil, fmt.Errorf("query login roles: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
	}

	details := [][]string{{"Role", "Connection Limit"}}
	count := 0
	for rows.Next() {
		var name string
		var connLimit int
		if err := rows.Scan(&name, &connLimit); err != nil {
			return nil, fmt.Errorf("scan login role: %w", err)
		}
		limit := "unlimited"
		if connLimit >= 0 {
			limit = fmt.Sprintf("%d", connLimit)
		}
		details = append(details, []string{name, limit})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate login roles: %w", err)
	}

	result.Details = details
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d login roles (excluding superusers). Review for appropriate access.", count),
	})

	return result, nil
}

// --- Check 4.5 ---

type check_4_5 struct{}

func (c *check_4_5) ID() string { return "4.5" }

func (c *check_4_5) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_4_5) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT n.nspname, p.proname, r.rolname, p.prosecdef, p.proconfig
		FROM pg_proc p
		JOIN pg_namespace n ON p.pronamespace = n.oid
		JOIN pg_roles r ON p.proowner = r.oid
		WHERE (p.prosecdef OR NOT p.proconfig IS NULL)
		AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		ORDER BY n.nspname, p.proname`)
	if err != nil {
		return nil, fmt.Errorf("query security definer functions: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	details := [][]string{{"Schema", "Function", "Owner", "Security Definer", "Config"}}
	count := 0
	for rows.Next() {
		var schema, funcName, owner string
		var secDef bool
		var config *string
		if err := rows.Scan(&schema, &funcName, &owner, &secDef, &config); err != nil {
			return nil, fmt.Errorf("scan function: %w", err)
		}
		secDefStr := "no"
		if secDef {
			secDefStr = "yes"
		}
		configStr := ""
		if config != nil {
			configStr = *config
		}
		details = append(details, []string{schema, funcName, owner, secDefStr, configStr})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate functions: %w", err)
	}

	if count == 0 {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "No SECURITY DEFINER functions found outside system schemas.",
		})
	} else {
		result.Status = checker.StatusFail
		result.Details = details
		result.Messages = append(result.Messages, checker.Message{
			Level:   "WARNING",
			Content: fmt.Sprintf("Found %d functions with SECURITY DEFINER or custom config outside system schemas.", count),
		})
	}

	return result, nil
}

// --- Check 4.6 ---

type check_4_6 struct{}

func (c *check_4_6) ID() string { return "4.6" }

func (c *check_4_6) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_4_6) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT grantee, table_schema, table_name, privilege_type
		FROM information_schema.table_privileges
		WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
		AND grantee NOT IN ('postgres')
		AND grantee != 'PUBLIC'
		ORDER BY grantee, table_schema, table_name`)
	if err != nil {
		return nil, fmt.Errorf("query DML privileges: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	details := [][]string{{"Grantee", "Schema", "Table", "Privilege"}}
	count := 0
	for rows.Next() {
		var grantee, schema, table, privilege string
		if err := rows.Scan(&grantee, &schema, &table, &privilege); err != nil {
			return nil, fmt.Errorf("scan privilege: %w", err)
		}
		details = append(details, []string{grantee, schema, table, privilege})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate privileges: %w", err)
	}

	if count == 0 {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "No excessive DML privileges found.",
		})
	} else {
		result.Status = checker.StatusManual
		result.Details = details
		result.Messages = append(result.Messages, checker.Message{
			Level:   "INFO",
			Content: fmt.Sprintf("Found %d DML privilege grants to non-superuser roles. Review for necessity.", count),
		})
	}

	return result, nil
}

// --- Check 4.7 ---

type check_4_7 struct{}

func (c *check_4_7) ID() string { return "4.7" }

func (c *check_4_7) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_4_7) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON c.relnamespace = n.oid
		WHERE c.relkind = 'r'
		AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		AND c.relrowsecurity = true
		ORDER BY n.nspname, c.relname`)
	if err != nil {
		return nil, fmt.Errorf("query RLS tables: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
	}

	details := [][]string{{"Schema", "Table", "RLS Enabled", "RLS Forced"}}
	count := 0
	for rows.Next() {
		var schema, table string
		var rlsEnabled, rlsForced bool
		if err := rows.Scan(&schema, &table, &rlsEnabled, &rlsForced); err != nil {
			return nil, fmt.Errorf("scan RLS table: %w", err)
		}
		details = append(details, []string{schema, table, fmt.Sprintf("%v", rlsEnabled), fmt.Sprintf("%v", rlsForced)})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate RLS tables: %w", err)
	}

	if count > 0 {
		result.Details = details
	}
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d tables with Row Level Security enabled. Review policies.", count),
	})

	return result, nil
}

// --- Check 4.8 ---

type check_4_8 struct{}

func (c *check_4_8) ID() string { return "4.8" }

func (c *check_4_8) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true, Superuser: true}
}

func (c *check_4_8) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	rows, err := env.DB.Query(ctx, `
		WITH RECURSIVE roltree AS (
			SELECT u.rolname, u.oid, u.rolcanlogin, u.rolsuper, '{}'::name[] AS rolparents,
				NULL::oid AS parent_roloid, NULL::name AS parent_rolname
			FROM pg_authid u
			LEFT JOIN pg_auth_members m ON u.oid = m.member
			WHERE m.roleid IS NULL
			UNION ALL
			SELECT u.rolname, u.oid, u.rolcanlogin, u.rolsuper,
				t.rolparents || g.rolname, g.oid, g.rolname
			FROM pg_authid u
			JOIN pg_auth_members m ON u.oid = m.member
			JOIN pg_authid g ON g.oid = m.roleid
			JOIN roltree t ON t.oid = g.oid
		)
		SELECT rolname, rolcanlogin, rolsuper, rolparents FROM roltree ORDER BY rolname`)
	if err != nil {
		return nil, fmt.Errorf("query role hierarchy: %w", err)
	}
	defer rows.Close()

	result := &checker.CheckResult{
		Status:   checker.StatusManual,
		Severity: checker.SeverityInfo,
	}

	details := [][]string{{"Role", "Can Login", "Superuser", "Parent Roles"}}
	count := 0
	for rows.Next() {
		var name string
		var canLogin, isSuper bool
		var parents []string
		if err := rows.Scan(&name, &canLogin, &isSuper, &parents); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		parentStr := ""
		if len(parents) > 0 {
			parentStr = strings.Join(parents, ", ")
		}
		details = append(details, []string{name, fmt.Sprintf("%v", canLogin), fmt.Sprintf("%v", isSuper), parentStr})
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}

	result.Details = details
	result.Messages = append(result.Messages, checker.Message{
		Level:   "INFO",
		Content: fmt.Sprintf("Found %d roles in the privilege hierarchy. Review for least-privilege compliance.", count),
	})

	return result, nil
}

// --- Check 4.10 ---

type check_4_10 struct{}

func (c *check_4_10) ID() string { return "4.10" }

func (c *check_4_10) Requirements() checker.CheckRequirements {
	return checker.CheckRequirements{SQLOnly: true}
}

func (c *check_4_10) Run(ctx context.Context, env *checker.Environment) (*checker.CheckResult, error) {
	var nspacl *string
	err := env.DB.QueryRow(ctx, "SELECT nspacl::text FROM pg_namespace WHERE nspname = 'public'").Scan(&nspacl)
	if err != nil {
		return nil, fmt.Errorf("query public schema ACL: %w", err)
	}

	result := &checker.CheckResult{Severity: checker.SeverityWarning}

	if nspacl == nil {
		// NULL means default privileges (which includes CREATE for PUBLIC)
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "WARNING",
			Content: "Public schema has default privileges (NULL ACL), which grants CREATE to PUBLIC.",
		})
		return result, nil
	}

	acl := *nspacl
	// Check if PUBLIC (represented by entries without a specific role before =) has CREATE
	// ACL format: {=UC/postgres,postgres=UC/postgres}
	// "=UC" means PUBLIC has Usage and Create
	hasPublicCreate := false
	for entry := range strings.SplitSeq(strings.Trim(acl, "{}"), ",") {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 && parts[0] == "" {
			// This is the PUBLIC entry
			privs := strings.SplitN(parts[1], "/", 2)[0]
			if strings.Contains(strings.ToUpper(privs), "C") {
				hasPublicCreate = true
				break
			}
		}
	}

	if hasPublicCreate {
		result.Status = checker.StatusFail
		result.Messages = append(result.Messages, checker.Message{
			Level:   "WARNING",
			Content: fmt.Sprintf("Public schema grants CREATE to PUBLIC. ACL: %s", acl),
		})
	} else {
		result.Status = checker.StatusPass
		result.Messages = append(result.Messages, checker.Message{
			Level:   "SUCCESS",
			Content: "Public schema does not grant CREATE to PUBLIC.",
		})
	}

	return result, nil
}
