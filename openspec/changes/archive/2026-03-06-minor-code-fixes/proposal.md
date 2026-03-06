## Why

Several small code quality issues were identified during analysis. Each is low-risk and independently valuable, but too small for its own change.

## What Changes

- Replace custom `indexOf` function in `runner.go` with `strings.IndexByte` from stdlib
- Compile regexes at package level in `detect.go` instead of per-call
- Remove redundant manual superuser check in `check4_8.Run()` (already handled by `Requirements().Superuser`)
- Stop silently swallowing errors in `detect.go` database/superuser list queries — log warnings to stderr

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `internal/checker/runner.go` — remove `indexOf` function, use `strings.IndexByte`
- `internal/environment/detect.go` — package-level compiled regexes, error handling for queries
- `internal/checks/section4/section4.go` — remove dead code in `check4_8`
