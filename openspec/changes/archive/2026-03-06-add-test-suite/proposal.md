## Why

The project has zero test files. For a security auditing tool, this is a critical gap — there is no way to verify that checks produce correct results, that the HBA parser handles edge cases, or that refactoring doesn't break behavior. CI runs `go test -race` but tests nothing.

## What Changes

- Add unit tests for the `checker` package (runner logic, filtering, skip conditions, registry)
- Add unit tests for the `hba` package (file parser, SQL parser, auth method classification)
- Add unit tests for the `netmask` package (CIDR parsing, network size calculation)
- Add unit tests for the `report` package (builder logic, JSON output, summary counts)
- Add unit tests for the `config` package (YAML loading, profile application, ConnString generation)
- Add a mock `DBQuerier` implementation for testing check implementations
- Add example tests for a representative set of checks

## Capabilities

### New Capabilities

- `test-infrastructure`: Test helpers, mocks, and fixtures for the pgharden test suite

### Modified Capabilities

## Impact

- New `*_test.go` files across `internal/checker/`, `internal/hba/`, `internal/netmask/`, `internal/report/`, `internal/config/`
- New test helper/mock file in `internal/checker/` for `DBQuerier` mock
- No changes to production code
