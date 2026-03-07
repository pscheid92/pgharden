# pgharden

Automated security assessment tool for PostgreSQL databases, following [CIS Benchmark](https://www.cisecurity.org/benchmark/postgresql) recommendations.

Single static binary. Single persistent connection. Works on bare metal, containers, RDS, and any managed service.

## Features

- **85 security checks** across 8 categories (installation, file permissions, logging, user access, connections, settings, replication, special config)
- **Single binary** — no runtime dependencies, no `psql`, no Perl
- **Single persistent connection** via [pgx](https://github.com/jackc/pgx) — not 80+ subprocess spawns
- **Environment-aware** — auto-detects capabilities and gracefully skips checks that can't run
- **pg_hba.conf via SQL** — uses `pg_hba_file_rules` view on PG 15+, falls back to file parsing on older versions
- **Three output formats** — colored text for terminals, JSON for CI/CD, self-contained HTML for reports
- **Smart format detection** — text when writing to a terminal, JSON when piped or redirected to a file
- **Meaningful exit codes** — `0` all passed, `1` critical failures, `2` non-critical failures, `3` tool error
- **Config file support** — YAML with named profiles

## Quick Start

```bash
# Build
go build -o pgharden ./cmd/pgharden

# Run against a local PostgreSQL (colored text output to terminal)
pgharden -H localhost -p 5432 -U postgres -d postgres

# Save JSON report (auto-detected when writing to file)
pgharden -H localhost -U postgres -d postgres -o results.json

# Save HTML report
pgharden --dsn "host=db.example.com user=auditor dbname=prod sslmode=require" -f html -o report.html

# Run only specific sections or checks
pgharden --section 3                    # Logging checks only
pgharden --include 5.3,5.4,5.12        # Specific checks only
pgharden --exclude 1.5                  # Skip specific checks
```

## Examples

### Local PostgreSQL

```bash
# Colored text to terminal (auto-detected)
pgharden -H localhost -U postgres -d postgres

# JSON to stdout (explicit format)
pgharden -H localhost -U postgres -d postgres -f json

# HTML report to file
pgharden -H localhost -U postgres -d postgres -f html -o report.html
```

### Docker / Container

```bash
# Against a PostgreSQL container (filesystem checks auto-skipped)
pgharden --dsn "host=localhost port=5432 user=postgres password=secret dbname=postgres sslmode=disable"
```

### AWS RDS / Aurora / Cloud SQL

```bash
# Managed databases work out of the box — filesystem and OS checks are auto-skipped
pgharden --dsn "host=mydb.abc123.us-east-1.rds.amazonaws.com port=5432 user=auditor password=secret dbname=prod sslmode=require"
```

### Non-superuser

```bash
# Works with limited privileges — superuser-only checks are auto-skipped
pgharden --dsn "host=db.example.com user=readonly dbname=prod sslmode=require"
```

### Focused audits

```bash
# Only connection & auth checks
pgharden --section 5 -H db.example.com -U auditor -d prod

# Only specific checks
pgharden --include 5.3,5.4,5.12,6.8 -H db.example.com -U auditor -d prod

# Everything except version check (requires internet)
pgharden --exclude 1.5 -H localhost -U postgres -d postgres
```

### CI/CD pipeline

```bash
pgharden --dsn "$DATABASE_URL" -f json -o results.json
EXIT_CODE=$?

# Parse results with jq
jq '.summary' results.json

# Fail the pipeline on critical findings
if [ $EXIT_CODE -eq 1 ]; then
  echo "CRITICAL security issues found!"
  jq '.categories[].checks[] | select(.status == "FAIL" and .severity == "CRITICAL") | .id + ": " + .title' results.json
  exit 1
fi
```

### Multiple databases

```bash
# Only check specific databases
pgharden -H localhost -U postgres -d postgres --allow myapp,billing

# Exclude system databases
pgharden -H localhost -U postgres -d postgres --exclude-db template0,template1
```

## Installation

### From source

Requires Go 1.26+.

```bash
git clone https://github.com/pgharden/pgharden.git
cd pgharden
make build
```

### Pre-built binaries

See [Releases](https://github.com/pgharden/pgharden/releases).

## Usage

```
pgharden [flags]
pgharden version

Flags:
  -H, --host string          PostgreSQL server host (default "localhost")
  -p, --port int             PostgreSQL server port (default 5432)
  -U, --user string          PostgreSQL user (default "postgres")
  -d, --database string      Database to connect to (default "postgres")
      --dsn string           Full connection string (overrides host/port/user/database)
  -f, --format string        Output format: text, json, html (auto-detected)
  -o, --output string        Output file (default: stdout)
      --no-color             Disable colored output
      --title string         Report title
  -c, --config string        Path to YAML config file
      --profile string       Configuration profile to use
      --include strings      Only run these check IDs
      --exclude strings      Skip these check IDs
      --section string       Only run checks in this section
  -a, --allow strings        Only check these databases
  -e, --exclude-db strings   Exclude these databases
      --platform string      Override platform detection (bare-metal, container, zalando, rds, aurora)
      --local                Enable filesystem and OS command checks (use only on the PostgreSQL host)
```

### Format auto-detection

When `-f` is not specified, the output format is chosen automatically:

- **Terminal** (stdout is a TTY) → `text` with color
- **File** (`-o report.json`) → `json`
- **Pipe** (`pgharden | jq`) → `json`

Color is enabled by default for text output to a terminal. Disable with `--no-color` or the `NO_COLOR` environment variable.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | At least one CRITICAL failure |
| 2 | Non-critical check failures |
| 3 | Tool error (connection failed, bad config) |

Use in CI/CD:

```bash
pgharden --dsn "$DATABASE_URL" -f json -o results.json
case $? in
  0) echo "All clear" ;;
  1) echo "CRITICAL issues found" && exit 1 ;;
  2) echo "Non-critical failures found" ;;
  3) echo "Tool error" && exit 1 ;;
esac
```

## Security Checks

85 checks across 8 sections:

1. **Installation and Patches** — repositories, systemd, checksums, version, extensions
2. **Directory and File Permissions** — umask, PGDATA, pg_hba.conf, socket permissions
3. **Logging and Auditing** — 27 checks for log settings, syslog, pgAudit
4. **User Access and Authorization** — superusers, SECURITY DEFINER, RLS, public schema
5. **Connection and Login** — authentication methods, SSL, CIDR ranges, password encryption
6. **PostgreSQL Settings** — runtime parameters, TLS, ciphers, FIPS, anonymization
7. **Replication** — replication users, WAL archiving, streaming SSL
8. **Special Configuration** — backup tools, external file references

See [docs/checks.md](docs/checks.md) for the full listing with requirements and environment compatibility.

## Documentation

- [docs/checks.md](docs/checks.md) — Complete check reference with IDs, descriptions, requirements, and environment compatibility
- [docs/config.md](docs/config.md) — Config file format, profiles, output formats, and environment detection

## Acknowledgments

The security checks in pgharden are derived from [pgdsat](https://github.com/darold/pgdsat) by Gilles Darold (HexaCluster Corp), originally licensed under GPLv3. pgharden is a clean-room reimplementation in Go — no Perl source code was copied — but the check logic, SQL queries, and expected values are based on his work.

Check descriptions reference the [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql), licensed under [Creative Commons BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

## License

GPLv3 — see [LICENSE](LICENSE).
