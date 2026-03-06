## Context

Section3 contains ~20 checks that follow identical logic: query a PostgreSQL setting via `SHOW`, compare against an expected value, return pass/fail with a message. Each is a separate struct with duplicated `ID()`, `Requirements()`, and `Run()` methods differing only in the setting name, expected value, severity, and messages.

## Goals / Non-Goals

**Goals:**
- Eliminate the repetitive boilerplate in section3 (and applicable checks elsewhere)
- Provide a data-driven `SettingCheck` struct that covers common comparison patterns
- Keep the implementation simple — no over-abstraction

**Non-Goals:**
- Replacing all checks with data-driven implementations (complex checks with branching logic stay as-is)
- Adding a DSL or configuration file for checks

## Decisions

1. **`SettingCheck` struct in `internal/checker/`**: A public struct implementing `Check` that accepts configuration fields: `CheckID`, `Setting` (the PG setting name), `Expected` (the desired value), `Comparator` (equals, not-equals, contains, one-of), `Sev` (severity), and `Reqs` (requirements).

2. **Comparator as a simple string enum**: Support `eq`, `neq`, `contains`, `oneof` comparators. `eq` is the default. This covers all current section3 patterns.

3. **Registration via slice literal in `init()`**: Each section file defines a `[]checker.SettingCheck` slice and registers all entries in a loop. This is compact and readable.

4. **Keep complex checks as custom structs**: Checks like 3.2 (pgaudit with multi-step logic) and 3.1.22 (log_line_prefix token check) remain as hand-written structs.

## Risks / Trade-offs

- Adding a generic check type increases indirection slightly, but the massive reduction in duplication is worth it.
- The comparator set is intentionally minimal — only add what's needed.
