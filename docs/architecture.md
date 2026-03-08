# Architecture

## Overview

pgharden uses hexagonal architecture (ports and adapters) with a strict dependency rule:

```
Domain ← Platform ← App ← Adapter ← CLI
```

Each layer may only import from layers to its left.

## Package Layout

```
cmd/pgharden/          Entry point — calls cli.Execute(), maps exit codes
internal/
├── domain/            Pure types and interfaces (zero internal imports)
├── platform/
│   ├── config/        YAML config, profiles, CLI-to-connstring mapping
│   ├── labels/        Human-readable titles and descriptions for checks/sections
│   └── buildinfo/     Version, commit, date (set via -ldflags)
├── app/
│   ├── scanner/       Scan pipeline orchestrator — wires runner + report builder
│   ├── runner/        Check executor — filtering, requirement checks, error handling
│   ├── checks/        Registry (All()) + section1–8 check implementations
│   ├── hba/           pg_hba.conf parser (SQL view on PG 15+, file fallback)
│   └── report/        Report struct + builder (RunResult[] → Report)
├── adapter/
│   ├── postgres/      pgx connection + privilege detection
│   ├── environment/   Runtime detection (version, platform, capabilities)
│   └── output/        Text, JSON, HTML renderers
└── cli/               Cobra commands, flag wiring, 3 interfaces (Connector, Detector, ReportWriter)
```

## Pipeline

```
1. Connect         Establish a single connection to PostgreSQL
2. Detect          Discover what the environment supports (version, privileges, platform, filesystem)
3. Run Checks      Select applicable checks, verify requirements, execute each one
4. Build Report    Group results by section, compute pass/fail summary
5. Render          Write text, JSON, or HTML to stdout or a file
```

The CLI parses flags, loads config, then drives each stage through injected interfaces (`Connector`, `Detector`, `ReportWriter`). The scanner wires stages 3–4: it creates a `Runner` with all checks from the registry, applies filter options, runs them, and passes results to the report builder. Exit code is derived from the report: 0 (all pass), 1 (critical failures), 2 (non-critical failures), 3 (tool error).

## Check Interface

```go
type Check interface {
    ID() string
    Reference() *Reference
    Requirements() CheckRequirements
    Run(ctx context.Context, env *Environment) (*CheckResult, error)
}
```

`Run()` receives the full `*Environment`, which carries:
- `env.DB` — `DBQuerier` for SQL queries
- `env.GetFS()` — `fs.FS` (defaults to `os.DirFS("/")` when nil)
- `env.GetCmd()` — `CommandRunner` (defaults to `exec.Command` when nil)

## Check Registration

`app/checks/registry.go` exposes `All()`, which calls each section's `Checks()` function and returns the combined slice sorted by ID. No init-time self-registration.

## Check Types

Most checks are custom structs. The `SettingCheck` struct handles the common pattern of comparing a single `pg_settings` value:

```go
type SettingCheck struct {
    CheckID, Setting, Expected, Comparator string  // comparators: eq, neq, contains, oneof
    Sev  Severity
    Reqs CheckRequirements
    Ref  *Reference
}
```

## Source Attribution

Each check returns a `*Reference` from `Reference()`:

```go
type Reference struct {
    Source string  // e.g., "CIS PostgreSQL 16 Benchmark v1.0.0"
    ID     string  // original ID in that source
    URL    string  // optional link
}
```

All current checks reference the CIS PostgreSQL 16 Benchmark via the `CISRef()` helper. Checks may return `nil` to indicate no external source. The `--source` flag filters by substring match (case-insensitive) against `Reference.Source`.

## Runner Filtering and Requirements

The runner applies two layers before executing a check:

**Filters** (`shouldSkip`) — skip without producing a result:
- `IncludeChecks` / `ExcludeChecks` — by check ID
- `IncludeSection` — by section prefix (via `SectionID()`)
- `IncludeSource` — by reference source substring

**Requirements** (`runOne`) — skip with a SKIPPED result and reason:
- `SkipPlatforms` — platform not applicable
- `MinPGVersion` — PG version too old
- `Superuser` — not superuser or RDS superuser
- `PGMonitor` — not pg_monitor member (superuser also satisfies this)
- `Filesystem` — no filesystem access
- `Commands` — required system commands not found

## HBA Parser

The `app/hba` package parses `pg_hba.conf` for authentication checks. On PG 15+ it reads the `pg_hba_file_rules` SQL view via `LoadFromSQL()`. On older versions it falls back to `LoadFromFile()` via `fs.FS`. The parser handles `include`, `include_if_exists`, and `include_dir` directives (max depth 10). `ClassifyAuthMethod()` categorizes methods as Secure, Weak, Forbidden, or Reject.

## Interfaces (Mockable Boundaries)

| Interface | Package | Production Impl | Test Double |
|-----------|---------|-----------------|-------------|
| `Connector` | `cli` | `dbConnector` (pgx) | `mockConnector` |
| `Detector` | `cli` | `envDetector` | `mockDetector` |
| `ReportWriter` | `cli` | `cliReportWriter` | `bufferWriter` |
| `DBQuerier` | `domain` | `*pgx.Conn` | `pgxmock` |
| `fs.FS` | stdlib | `os.DirFS("/")` | `fstest.MapFS` |
| `CommandRunner` | `domain` | `osCommandRunner` | `mockCmd` (map-based) |

CLI tests mock only the top three — no SQL mocking needed. Check-level tests mock the bottom three via `Environment` fields.

## Testing

- **Unit** — Each check package uses `pgxmock` + `fstest.MapFS` + `mockCmd`. Scanner, runner, report, and output packages have standalone tests.
- **CLI** — `cli/` tests use `mockConnector`, `mockDetector`, and `bufferWriter` to exercise the full pipeline without infrastructure.
- **E2E** — `integration_test.go` uses testcontainers with `postgres:16-alpine`.

```bash
go test ./... -short    # unit + CLI (no Docker)
go test ./... -count=1  # includes E2E (needs Docker)
```
