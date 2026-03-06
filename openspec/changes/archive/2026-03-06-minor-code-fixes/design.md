## Context

Several small code quality issues identified during analysis. Each is independent and low-risk.

## Goals / Non-Goals

**Goals:**
- Fix the 4 identified minor issues in a single change

**Non-Goals:**
- Larger refactors — keep each fix surgical

## Decisions

1. **`indexOf` → `strings.IndexByte`**: Direct replacement in `runner.go:71-78`. Delete the custom function.

2. **Package-level compiled regexes in `detect.go`**: Move `regexp.MustCompile` calls to `var` declarations at package scope. Affects `parseMajorVersion` and `detectContainer`.

3. **Remove redundant superuser check in `check4_8`**: The `Requirements()` method already declares `Superuser: true`, and the runner skips the check if the user isn't a superuser. The manual check in `Run()` (lines 378-383) is dead code.

4. **Log warnings for failed queries in `Detect()`**: For the database list and superuser list queries (lines 60-81), log a warning to stderr instead of silently continuing with empty slices. Use `fmt.Fprintf(os.Stderr, ...)` consistent with other status output in the codebase.

## Risks / Trade-offs

- All fixes are low-risk mechanical changes.
- The new stderr warnings in `Detect()` add output that wasn't there before, but only on error conditions that would otherwise cause silent misbehavior.
