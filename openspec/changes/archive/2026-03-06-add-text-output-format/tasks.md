## 1. Text renderer

- [x] 1.1 Create `internal/report/text.go` with `WriteText(w io.Writer, r *Report, color bool) error`
- [x] 1.2 Implement section-grouped output: section header, then each check with `[PASS]`/`[FAIL]`/`[SKIP]`/`[MANUAL]` prefix, check ID, title, and messages on subsequent indented lines
- [x] 1.3 Add summary line at the end: "X passed, Y failed, Z skipped, W manual (N total)"
- [x] 1.4 Implement ANSI color support: green for PASS, red for FAIL/CRITICAL, yellow for WARNING, gray for SKIP — controlled by the `color` parameter

## 2. CLI integration

- [x] 2.1 Add `--no-color` flag to cobra command in `main.go`
- [x] 2.2 Add smart default format logic: detect if stdout is a TTY (`os.Stdout.Stat()` checking `ModeCharDevice`); if TTY and no explicit `--format`, default to `text`; if file output and no explicit `--format`, default to `json`
- [x] 2.3 Add color auto-detection: enable color when format is `text`, output is a TTY, `--no-color` is not set, and `NO_COLOR` env var is not set
- [x] 2.4 Add the `text` case to the format switch in `run()`, calling `report.WriteText(out, rpt, useColor)`

## 3. Verification

- [x] 3.1 Verify `go build ./cmd/pgharden` compiles
- [x] 3.2 Test `text` format output renders correctly (manually or with a test)
