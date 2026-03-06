## Why

`os.Exit(1)` and `os.Exit(2)` are called inside the `run()` function (`cmd/pgharden/main.go:161-165`), which bypasses all deferred cleanup — including `conn.Close()` and `out.Close()`. This is a real bug that can leak database connections and leave output files in an inconsistent state.

## What Changes

- Remove `os.Exit` calls from the `run()` function
- Return exit code information from `run()` back to `main()`
- `main()` handles exit codes after all defers have executed

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `cmd/pgharden/main.go` — `run()` signature changes to return exit code info; `main()` updated to call `os.Exit` after defers complete
- No external API or behavioral changes — exit codes remain the same (1 for critical, 2 for failures, 3 for errors)
