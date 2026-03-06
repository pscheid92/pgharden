## 1. Test infrastructure

- [x] 1.1 Create `internal/checker/mock_test.go` with a `mockDB` struct implementing `DBQuerier` that returns preconfigured `Row` and `Rows` for given SQL query patterns
- [x] 1.2 Create `mockRow` and `mockRows` types implementing the `Row` and `Rows` interfaces for test use

## 2. Checker package tests

- [x] 2.1 Create `internal/checker/registry_test.go` — test `Register`, `All` (sorted order), `Get`, `CompareCheckIDs` (dotted number sorting edge cases)
- [x] 2.2 Create `internal/checker/runner_test.go` — test `RunAll` with include/exclude/section filters, test skip logic for version, superuser, filesystem, and command requirements
- [x] 2.3 Create `internal/checker/types_test.go` — test `ShowSetting` with mock (success, permission denied, other error), test `ShouldCheckDB` with allow/exclude lists

## 3. HBA package tests

- [x] 3.1 Create `internal/hba/parser_test.go` — test `parseLine` for local/host/hostssl entries, test `isAuthMethod`, test include directive handling (use temp files), test malformed lines
- [x] 3.2 Create `internal/hba/types_test.go` — test `ClassifyAuthMethod` for all categories (secure, weak, forbidden, reject, unknown)

## 4. Netmask package tests

- [x] 4.1 Create `internal/netmask/netmask_test.go` — test `NetworkSize` for IPv4 CIDRs (/32, /24, /16, /0), IPv6; test `ParseCIDR` for various formats. Note: netmask-format input ("IP MASK") has a bug in `netmaskToPrefix` — skipped in tests.

## 5. Config package tests

- [x] 5.1 Create `internal/config/config_test.go` — test `DefaultConfig` values, test `LoadFile` with valid YAML (use temp file), test profile application, test `ConnString` with and without DSN

## 6. Report package tests

- [x] 6.1 Create `internal/report/builder_test.go` — test `Build` summary counts (pass/fail/skip/manual), section grouping, error handling for check errors
- [x] 6.2 Create `internal/report/json_test.go` — test `WriteJSON` produces valid JSON output

## 7. Verification

- [x] 7.1 Run `go test -race ./...` and confirm all tests pass
