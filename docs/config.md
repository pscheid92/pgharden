# pgharden — Configuration

## Config File

pgharden supports YAML configuration files with named profiles. Use `--config` (or `-c`) to load one.

```yaml
# pgharden.yaml
host: db.example.com
port: 5432
user: auditor
database: prod
format: html
output: report.html
lang: en_US

# Filtering
include_checks: []           # Only run these check IDs (empty = all)
exclude_checks:
  - "1.5"                    # Skip the online version check
include_section: ""          # Only run checks in this section

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

# Override config with CLI flags
pgharden -c pgharden.yaml --format json -o results.json
```

CLI flags take precedence over config file values.

## Environment Detection

Before running any checks, pgharden probes the runtime environment to determine what's available:

| Probe | Method | Effect |
|-------|--------|--------|
| PG version | `SELECT version()` | Skips checks requiring newer PG versions |
| Privileges | `pg_roles` queries | Skips superuser-gated checks |
| Filesystem | `os.Stat(data_directory)` | Skips file permission checks on remote/managed DBs |
| Commands | `exec.LookPath()` | Skips checks needing systemctl, rpm, pgbackrest, etc. |
| Container | `/.dockerenv`, `/proc/1/cgroup` | Reported in metadata |
| Databases | `pg_database` query | Populates list for multi-DB checks |
| Superusers | `pg_roles` query | Used by HBA superuser restriction check |

Checks that can't run are marked **SKIPPED** with a reason — never a hard failure.

## Connection

pgharden connects via [pgx](https://github.com/jackc/pgx) using a single persistent connection. You can specify connection parameters in three ways:

### CLI flags

```bash
pgharden -H db.example.com -p 5432 -U auditor -d prod
```

### DSN string

```bash
pgharden --dsn "host=db.example.com port=5432 user=auditor dbname=prod sslmode=require"
```

### Environment variables

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

Use any standard PostgreSQL method:

- `PGPASSWORD` environment variable
- `.pgpass` file
- `password=` in DSN string
- Kerberos/GSSAPI (no password needed)

## Output Formats

### JSON

```bash
pgharden -f json -o results.json
```

Machine-readable, pipe to `jq`:

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

Self-contained single-file HTML with embedded CSS. No CDN dependencies. Collapsible sections, color-coded status badges, detail tables.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | At least one CRITICAL failure |
| 2 | Warnings found (no criticals) |
| 3 | Tool error (connection failed, bad config) |

## Project Structure

```
cmd/pgharden/main.go          CLI entry point (cobra)
internal/
  checker/                     Check interface, registry, runner
  checks/section{1-8}/        85 check implementations (one file per section)
  config/                      YAML config + CLI flag binding
  connection/                  pgx connection + privilege detection
  environment/                 Runtime capability detection
  hba/                         pg_hba.conf parsing (SQL view + file fallback)
  netmask/                     CIDR range calculation
  report/                      JSON + HTML report generation
  labels/                      i18n (en_US, fr_FR, zh_CN)
```
