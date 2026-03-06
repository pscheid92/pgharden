## 1. Replace custom indexOf

- [x] 1.1 In `internal/checker/runner.go`, replace the call to `indexOf(id, '.')` with `strings.IndexByte(id, '.')` and delete the `indexOf` function

## 2. Compile regexes at package level

- [x] 2.1 In `internal/environment/detect.go`, move `regexp.MustCompile(`PostgreSQL (\d+)`)` to a package-level `var` (e.g., `pgVersionRe`)
- [x] 2.2 Move `regexp.MustCompile(`docker|kubepods|containerd`)` to a package-level `var` (e.g., `containerRe`)
- [x] 2.3 Update `parseMajorVersion` and `detectContainer` to use the package-level variables

## 3. Remove redundant superuser check

- [x] 3.1 In `internal/checks/section4/section4.go`, remove the manual `if !env.IsSuperuser` check and early return in `check4_8.Run()` (lines 378-383) — the runner already handles this via `Requirements().Superuser`

## 4. Fix error swallowing in Detect()

- [x] 4.1 In `internal/environment/detect.go`, add `fmt.Fprintf(os.Stderr, "Warning: ...")` when the database list query fails (line 60-68)
- [x] 4.2 Add similar stderr warning when the superuser list query fails (lines 72-81)

## 5. Verification

- [x] 5.1 Verify `go build ./cmd/pgharden` compiles
- [x] 5.2 Verify `go vet ./...` passes
