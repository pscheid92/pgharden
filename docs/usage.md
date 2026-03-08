# Usage Guide

## Quick Start

```bash
# Basic scan against a local PostgreSQL instance
pgharden -H localhost -U postgres -d postgres

# Save results as JSON
pgharden -H localhost -U postgres -d postgres -f json -o results.json

# Generate a self-contained HTML report
pgharden -H localhost -U postgres -d postgres -f html -o report.html

# Run only section 3 checks (Logging and Auditing)
pgharden -H localhost -U postgres -d postgres --section 3

# Run only CIS benchmark checks
pgharden -H localhost -U postgres -d postgres --source cis
```

## Connection

pgharden connects via [pgx](https://github.com/jackc/pgx) using a single persistent connection. There are three ways to specify connection parameters.

### CLI Flags

```bash
pgharden -H db.example.com -p 5432 -U auditor -d prod
```

| Flag | Description |
|------|-------------|
| `-H`, `--host` | PostgreSQL server host |
| `-p`, `--port` | PostgreSQL server port |
| `-U`, `--user` | PostgreSQL user |
| `-d`, `--database` | Database to connect to |

### DSN String

A full connection string overrides individual host/port/user/database flags:

```bash
pgharden --dsn "host=db.example.com port=5432 user=auditor dbname=prod sslmode=require"
```

### Environment Variables

pgx respects standard PostgreSQL environment variables:

```bash
export PGHOST=db.example.com
export PGPORT=5432
export PGUSER=auditor
export PGDATABASE=prod
export PGSSLMODE=require
pgharden
```

### Password

Use any standard PostgreSQL authentication method:

- `PGPASSWORD` environment variable
- `.pgpass` file
- `password=` in DSN string
- Kerberos/GSSAPI (no password needed)

## Filtering

### Check Filtering

| Flag | Description | Example |
|------|-------------|---------|
| `--include` | Only run these check IDs | `--include 3.1.2,3.1.4` |
| `--exclude` | Skip these check IDs | `--exclude 1.5` |
| `--section` | Only run checks in this section | `--section 3` |
| `--source` | Only run checks from this source | `--source cis` |

The `--source` flag filters checks by their reference source. For example, `--source cis` runs only checks that originate from the CIS PostgreSQL Benchmark. Checks without a matching source are skipped.

```bash
# Run only CIS benchmark checks
pgharden --source cis

# Run section 3, but skip check 3.2
pgharden --section 3 --exclude 3.2

# Run only specific checks
pgharden --include 3.1.2,3.1.4,5.1
```

### Database Filtering

| Flag | Description | Example |
|------|-------------|---------|
| `-a`, `--allow` | Only check these databases | `-a prod,staging` |
| `-e`, `--exclude-db` | Exclude these databases | `-e template0,template1` |

```bash
# Only audit the prod and staging databases
pgharden -a prod,staging

# Skip template databases
pgharden -e template0,template1
```

## Configuration File

pgharden supports YAML configuration files with named profiles. Use `--config` (or `-c`) to load one, and `--profile` to select a profile.

```yaml
# pgharden.yaml
host: db.example.com
port: 5432
user: auditor
database: prod
format: html
output: report.html

# Filtering
include_checks: []           # Only run these check IDs (empty = all)
exclude_checks:
  - "1.5"                    # Skip the online version check
include_section: ""          # Only run checks in this section
include_source: ""           # Only run checks from this source (e.g., "cis")

# Database filtering
allow_databases: []           # Only check these databases
exclude_databases:
  - template0
  - template1

# Profiles — named presets for common scenarios
profiles:
  ci:
    include_section: "3"
    exclude_checks: ["3.2"]
  connections-only:
    include_section: "5"
  full:
    exclude_checks: []
```

```bash
# Use a profile
pgharden -c pgharden.yaml --profile ci

# Override config values with CLI flags
pgharden -c pgharden.yaml --format json -o results.json
```

CLI flags take precedence over config file values.

## Environment Detection

Before running any checks, pgharden probes the runtime environment to determine what is available:

| Probe | Method | Effect |
|-------|--------|--------|
| PG version | `SELECT version()` | Skips checks requiring newer PG versions |
| Privileges | `pg_roles` queries | Skips superuser-gated checks |
| Filesystem | `os.Stat(data_directory)` | Skips file permission checks on remote/managed DBs |
| Commands | `exec.LookPath()` | Skips checks needing systemctl, rpm, pgbackrest, etc. |
| Container | `/.dockerenv`, `/proc/1/cgroup` | Reported in metadata |
| Databases | `pg_database` query | Populates list for multi-DB checks |
| Superusers | `pg_roles` query | Used by HBA superuser restriction check |

Checks that cannot run are marked **SKIPPED** with a reason -- never a hard failure.

### Platform Override

Use `--platform` to override auto-detection when pgharden misidentifies your environment:

```bash
pgharden --platform rds --dsn "..."
```

Valid values: `bare-metal`, `container`, `kubernetes`, `rds`, `aurora`.

### Local Mode

By default, filesystem and OS command checks are skipped when connecting to a remote database. Use `--local` when running pgharden directly on the PostgreSQL host to enable these checks:

```bash
pgharden --local -H localhost -U postgres -d postgres
```

## Output Formats

Three formats are available via `-f` / `--format`: `text`, `json`, and `html`.

When `-f` is not specified, the format is auto-detected:

- **Terminal** (stdout is a TTY) -- `text` with color
- **File** (`-o report.json`) -- `json`
- **Pipe** (`pgharden | jq`) -- `json`

### Text

```bash
pgharden -H localhost -U postgres -d postgres
```

Human-readable colored output for terminal use. Each check shows a status prefix (`[PASS]`, `[FAIL]`, `[SKIP]`, `[MANUAL]`) followed by the check ID and title, with indented messages below. A summary line shows passed/failed/skipped/manual counts and failures by severity.

Color is enabled by default when writing to a terminal. Disable with `--no-color` or the `NO_COLOR` environment variable.

### JSON

```bash
pgharden -f json -o results.json
```

Machine-readable output. Pipe to `jq` for extraction:

```bash
# Summary
pgharden -f json | jq '.summary'

# Failed checks only
pgharden -f json | jq '.categories[].checks[] | select(.status == "FAIL")'

# Critical findings
pgharden -f json | jq '.categories[].checks[] | select(.severity == "CRITICAL" and .status == "FAIL") | {id, title}'
```

### HTML

```bash
pgharden -f html -o report.html
```

Self-contained single-file HTML with embedded CSS and SVG icons. No CDN dependencies. Includes collapsible sections, color-coded status badges, and detail tables.

Additional output flags:

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Write to a file instead of stdout |
| `--no-color` | Disable colored terminal output |
| `--title` | Set a custom report title |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | At least one CRITICAL failure |
| 2 | Non-critical check failures (WARNING or lower) |
| 3 | Tool error (connection failed, bad config, etc.) |

Exit codes integrate directly with CI/CD pipelines:

- **Exit 0** -- pass the quality gate.
- **Exit 1** -- fail the pipeline on critical security findings.
- **Exit 2** -- optionally fail or warn on non-critical findings.
- **Exit 3** -- indicates a tooling problem, not a security finding.

```bash
# CI example: fail only on critical findings
pgharden -c pgharden.yaml --profile ci
if [ $? -eq 1 ]; then
  echo "Critical security findings detected"
  exit 1
fi
```
