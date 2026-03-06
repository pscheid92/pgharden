## 1. Create SettingCheck helper

- [x] 1.1 Create `internal/checker/setting_check.go` with a `SettingCheck` struct containing fields: `CheckID`, `Setting`, `Expected`, `Comparator` (string: eq/neq/contains/oneof), `Sev` (Severity), `Reqs` (CheckRequirements), `SuccessMsg`, `FailureMsg`
- [x] 1.2 Implement `ID()`, `Requirements()`, and `Run()` methods on `SettingCheck` to satisfy the `Check` interface
- [x] 1.3 In `Run()`, use `ShowSetting()` to query the value, handle `ErrPermissionDenied` with `SkippedPermission()`, and apply the comparator logic
- [x] 1.4 Support comparators: `eq` (default, exact match), `neq` (not equal), `contains` (substring), `oneof` (comma-separated list of acceptable values)

## 2. Refactor section3

- [x] 2.1 Identify all section3 checks that can be replaced by `SettingCheck` (all simple SHOW-and-compare checks: 3.1.2 through 3.1.27, excluding 3.2 and 3.1.22)
- [x] 2.2 Replace identified checks with a `[]SettingCheck` slice registered in a loop in `init()`
- [x] 2.3 Keep `check32` (pgaudit multi-step) and `check3122` (log_line_prefix token check) as custom structs
- [x] 2.4 Remove all replaced struct definitions and methods from section3.go

## 3. Apply to other sections

- [x] 3.1 Scan section6 and other sections for checks that follow the same SHOW-and-compare pattern
- [x] 3.2 Replace applicable checks with `SettingCheck` registrations (section7 check72 replaced; sections 6/8 have no simple SHOW-and-compare checks)

## 4. Verification

- [x] 4.1 Verify the code compiles: `go build ./cmd/pgharden`
- [x] 4.2 Verify `checker.All()` returns the same set of check IDs as before the refactor
