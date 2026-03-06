## 1. Fix exit code propagation

- [x] 1.1 Change `run()` to return `(int, error)` where `int` is the desired process exit code (0=clean, 1=critical, 2=failures)
- [x] 1.2 Remove `os.Exit(1)` and `os.Exit(2)` calls from inside `run()`, replacing them with return statements
- [x] 1.3 Update the cobra `RunE` handler to capture the exit code from `run()` in a closure variable accessible to `main()`
- [x] 1.4 In `main()`, call `os.Exit` with the captured exit code after `rootCmd.ExecuteContext` returns (so all defers in `run()` have completed)

## 2. Verification

- [x] 2.1 Verify the code compiles: `go build ./cmd/pgharden`
- [x] 2.2 Verify exit codes are preserved: critical findings exit 1, non-critical failures exit 2, errors exit 3, clean exit 0
