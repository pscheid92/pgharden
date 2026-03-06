## Context

The tool only supports `json` and `html` output formats. CLI users and CI pipelines need a quick text summary without parsing JSON or opening HTML.

## Goals / Non-Goals

**Goals:**
- Add a `text` format that renders a readable summary to the terminal
- Support ANSI colors when outputting to a TTY
- Provide a `--no-color` flag to disable colors

**Non-Goals:**
- Interactive/TUI mode
- Replacing JSON as the machine-readable format

## Decisions

1. **Format: grouped by section with status indicators**: Each check shows `[PASS]`, `[FAIL]`, `[SKIP]`, `[MANUAL]` prefix, check ID, title, and any messages. Sections are grouped with headers. A summary line at the end shows counts.

2. **Color implementation**: Use ANSI escape codes directly (no external dependency). Green for pass, red for fail/critical, yellow for warning, gray for skip. Auto-detect TTY via `os.Stdout.Stat()` — disable colors if not a terminal or if `--no-color` / `NO_COLOR` env var is set.

3. **Default format heuristic**: When `--format` is not explicitly set: use `text` for stdout, keep `json` when `--output` is specified. This gives the best default experience for both interactive and scripted use.

4. **Implementation in `internal/report/text.go`**: A `WriteText(w io.Writer, r *Report, color bool) error` function following the same pattern as `WriteJSON` and `WriteHTML`.

## Risks / Trade-offs

- Changing the default format is technically a breaking change for anyone piping stdout to `jq`. Mitigated by only changing the default when no explicit `--format` is given and output is a TTY.
- ANSI codes without a library means no Windows legacy console support, but modern Windows Terminal handles ANSI fine.
