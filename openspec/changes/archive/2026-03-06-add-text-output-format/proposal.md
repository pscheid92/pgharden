## Why

The tool only supports JSON and HTML output formats. For quick CLI usage and CI pipelines, a plain-text terminal-friendly format is the most practical option. Users currently have to parse JSON or open an HTML file to see results.

## What Changes

- Add a `text` output format that renders results as a readable terminal table/summary
- Make `text` the default format (instead of `json`) when outputting to stdout
- Keep `json` as the default when writing to a file (`--output`)
- Include color coding for pass/fail/skip when outputting to a terminal (with automatic detection and `--no-color` flag)

## Capabilities

### New Capabilities

- `text-report`: Terminal-friendly plain-text report renderer with optional ANSI color support

### Modified Capabilities

## Impact

- New file: `internal/report/text.go` — text renderer
- `internal/config/config.go` — default format logic
- `cmd/pgharden/main.go` — new format case, `--no-color` flag
- Docs updates for new format option
