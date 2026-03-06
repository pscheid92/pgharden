## 1. Define convention

- [x] 1.1 Adopt naming convention: `check_X_Y_Z` with underscores between all numeric segments matching the dotted check ID (e.g., check ID "5.1" -> `check_5_1`, "3.1.12" -> `check_3_1_12`)

## 2. Rename structs

- [x] 2.1 Rename all check structs in `internal/checks/section1/section1.go` to follow the convention
- [x] 2.2 Rename all check structs in `internal/checks/section2/section2.go` and `section2_windows.go`
- [x] 2.3 Rename all check structs in `internal/checks/section3/section3.go` (only custom structs remaining after extract-check-helper)
- [x] 2.4 Rename all check structs in `internal/checks/section4/section4.go`
- [x] 2.5 Rename all check structs in `internal/checks/section5/section5.go`
- [x] 2.6 Rename all check structs in `internal/checks/section6/section6.go`
- [x] 2.7 Rename all check structs in `internal/checks/section7/section7.go`
- [x] 2.8 Rename all check structs in `internal/checks/section8/section8.go`

## 3. Verification

- [x] 3.1 Verify the code compiles: `go build ./cmd/pgharden`
- [x] 3.2 Verify all `init()` registration calls reference the renamed structs
