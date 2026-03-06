## Why

The section3 checks (3.1.2 through 3.1.27) are nearly identical — each runs `SHOW <setting>`, compares against an expected value, and returns pass/fail. This pattern repeats ~20 times with only the setting name, expected value, and message differing. This creates ~500 lines of duplicated boilerplate that is tedious to maintain and error-prone to modify.

## What Changes

- Add a data-driven `settingCheck` helper struct that implements the `checker.Check` interface
- Replace the ~20 repetitive "SHOW setting == expected" checks in section3 with table-driven registrations
- Apply the same pattern to similar checks in other sections where applicable
- Reduce section3.go from ~825 lines to ~150 lines

## Capabilities

### New Capabilities

- `setting-check-helper`: A reusable, data-driven check implementation for PostgreSQL setting comparisons (equals, not-equals, contains, on/off patterns)

### Modified Capabilities

## Impact

- New file: `internal/checker/setting_check.go` — the helper implementation
- `internal/checks/section3/section3.go` — rewritten to use table-driven registrations
- Other section files may be simplified where the same pattern applies
- No behavioral changes — all checks produce identical results
