## Context

`run()` in `cmd/pgharden/main.go` calls `os.Exit(1)` and `os.Exit(2)` directly on lines 161-165, based on report severity. This terminates the process immediately, skipping deferred calls to `conn.Close(ctx)` (line 97) and `out.Close()` (line 141).

## Goals / Non-Goals

**Goals:**
- Ensure all deferred cleanup runs before the process exits
- Preserve the existing exit code semantics (0=clean, 1=critical, 2=failures, 3=errors)

**Non-Goals:**
- Changing exit code values or meanings
- Refactoring the overall command structure

## Decisions

1. **Return an exit code from `run()` instead of calling `os.Exit`**: Change `run()` to return `(int, error)` where the int is the desired exit code. `main()` captures this and calls `os.Exit` after `rootCmd.ExecuteContext` returns, ensuring all defers in `run()` have completed.

2. **Use a sentinel error or separate return value**: A separate `int` return is cleaner than encoding exit codes in error types — it avoids conflating "something went wrong" with "checks found issues."

## Risks / Trade-offs

- Minimal risk — this is a straightforward refactor with no behavioral change to external consumers.
- The cobra `RunE` function only returns `error`, so we'll store the exit code in a closure variable accessible to `main()`.
