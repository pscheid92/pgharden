# Code Review Checklist

## 1. Core types and abstractions
- [x] `internal/checker/types.go` — Check interface, Environment, DBQuerier, CheckResult helpers, ShowSetting, SortChecks
- [x] `internal/checker/setting_check.go` — data-driven check implementation
- [x] `internal/checker/runner.go` — executes checks with filtering and skip logic

## 2. Infrastructure
- [x] `internal/connection/connection.go` — Connect(), returns *pgx.Conn
- [x] `internal/connection/privileges.go` — DetectPrivileges() with pg_has_role
- [x] `internal/environment/detect.go` — PG version, privileges, filesystem, containers
- [x] `internal/config/config.go` — YAML config, profiles, ConnString
- [x] `internal/buildinfo/buildinfo.go` — version/commit/date injection

## 3. Supporting packages
- [x] `internal/hba/types.go` — auth method classification
- [x] `internal/hba/parser.go` — pg_hba.conf file parser + pg_hba_file_rules SQL loader
- [ ] `internal/netmask/netmask.go` — CIDR/netmask utilities
- [ ] `internal/labels/labels.go` — i18n lookup
- [ ] `internal/labels/en_us.go` — English labels (fr_fr.go, zh_cn.go same shape)

## 4. Check implementations (skim)
- [ ] `internal/checks/section3/section3.go` — best example: SettingCheck table + custom checks
- [ ] `internal/checks/section5/section5.go` — HBA-based checks, most complex
- [ ] `internal/checks/section1/section1.go` — filesystem + manual checks
- [ ] `internal/checks/section2/section2.go` — Unix permissions (+ section2_windows.go stub)
- [ ] `internal/checks/section4/section4.go` — roles, privileges, RLS
- [ ] `internal/checks/section6/section6.go` — runtime params, SSL, ciphers
- [ ] `internal/checks/section7/section7.go` — replication
- [ ] `internal/checks/section8/section8.go` — backups, special files

## 5. Output
- [ ] `internal/report/types.go` — report data structures
- [ ] `internal/report/builder.go` — assembles report from check results
- [ ] `internal/report/text.go` — terminal renderer
- [ ] `internal/report/json.go` — JSON output
- [ ] `internal/report/html.go` — HTML template

## 6. CLI layer
- [ ] `internal/cli/exitcode.go` — named exit codes
- [ ] `internal/cli/checks.go` — wires all 8 sections
- [ ] `internal/cli/output.go` — format resolution, color, file output
- [ ] `internal/cli/scan.go` — connect → run → write
- [ ] `internal/cli/root.go` — cobra setup, flags
- [ ] `internal/cli/version.go` — version subcommand
- [ ] `cmd/pgharden/main.go` — 15-line entrypoint

## 7. Tests
- [ ] `internal/checker/mock_test.go` — pgxmock helper
- [ ] `internal/checker/types_test.go` — ShowSetting, ShouldCheckDB, enums, sort
- [ ] `internal/checker/setting_check_test.go` — all comparators, errors
- [ ] `internal/checker/runner_test.go` — filtering, skip logic
- [ ] `internal/cli/integration_test.go` — full pipeline with testcontainers
- [ ] `internal/hba/parser_test.go` — file parsing, includes, auth methods
- [ ] `internal/hba/types_test.go` — auth method classification
- [ ] `internal/netmask/netmask_test.go` — CIDR, netmask format, IPv6
- [ ] `internal/config/config_test.go` — defaults, YAML, profiles, ConnString
- [ ] `internal/environment/detect_test.go` — parseMajorVersion
- [ ] `internal/labels/labels_test.go` — lookups, fallbacks, IsManual
- [ ] `internal/report/builder_test.go` — summary counts, section grouping
- [ ] `internal/report/json_test.go` — valid JSON output
- [ ] `internal/report/html_test.go` — renders without error
- [ ] `internal/report/text_test.go` — color/no-color output

## 8. CI/Build
- [ ] `Makefile`
- [ ] `.github/workflows/ci.yml`
- [ ] `.github/workflows/release.yml`
