## Why

Check struct names use inconsistent conventions within and across files: `check51` (no separator), `check5_2` (underscore), `check4_3` (underscore). This makes the codebase harder to navigate and grep. A consistent naming convention improves readability.

## What Changes

- Standardize all check struct names to use underscores between section and check number: `check_5_1`, `check_5_2`, `check_3_1_12`, etc.
- Rename all associated method receivers consistently
- Update all `init()` registration calls

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- All files in `internal/checks/section*/` — struct renames (no exported symbols, so no external impact)
- Pure refactor with no behavioral changes
