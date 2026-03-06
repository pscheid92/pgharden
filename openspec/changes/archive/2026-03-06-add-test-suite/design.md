## Context

The project has zero `_test.go` files. CI runs `go test -race` but executes no tests. Core logic (runner, HBA parser, netmask, config, report builder) has no verification.

## Goals / Non-Goals

**Goals:**
- Establish test coverage for core packages: `checker`, `hba`, `netmask`, `config`, `report`
- Create a reusable `DBQuerier` mock for testing checks without a real database
- Add representative check tests demonstrating how to test individual checks
- Target the most valuable tests first: parser correctness, runner filtering, report building

**Non-Goals:**
- 100% coverage — focus on correctness of core logic and edge cases
- Integration tests requiring a live PostgreSQL instance (future work)
- Testing the CLI/cobra layer

## Decisions

1. **Mock DBQuerier in `internal/checker/testutil_test.go`**: A simple mock that returns preconfigured rows for given queries. Uses a map of query string to results. Keeps test setup minimal.

2. **Table-driven tests throughout**: Use Go's `t.Run` with subtests for all test functions.

3. **Test file placement**: Each `_test.go` lives in the same package as the code it tests (white-box testing) to access internal types.

4. **No external test dependencies**: Use only stdlib `testing` — no testify or similar. Keep the dependency footprint minimal.

## Risks / Trade-offs

- Without a live database, check tests verify logic against mocked responses — they won't catch SQL syntax errors. This is acceptable for unit tests.
- The mock approach means tests need to know expected SQL queries, creating some coupling.
