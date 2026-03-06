## ADDED Requirements

### Requirement: Text report format
A `WriteText` function renders the report as human-readable plain text grouped by section.

#### Scenario: Basic text output
- **WHEN** `WriteText` is called with a report containing checks across multiple sections
- **THEN** output shows section headers, each check with status prefix (`[PASS]`, `[FAIL]`, `[SKIP]`, `[MANUAL]`), check ID, title, and messages, followed by a summary line

### Requirement: ANSI color support
When color is enabled, status indicators use ANSI escape codes for visual clarity.

#### Scenario: Color output to terminal
- **WHEN** `WriteText` is called with `color: true`
- **THEN** PASS is green, FAIL/CRITICAL is red, WARNING is yellow, SKIP is gray

#### Scenario: No-color output
- **WHEN** `WriteText` is called with `color: false`
- **THEN** no ANSI escape codes appear in output

### Requirement: Smart default format
The default output format adapts based on output destination.

#### Scenario: Stdout to terminal without explicit format
- **WHEN** `--format` is not specified and output goes to stdout (a TTY)
- **THEN** the `text` format is used with colors enabled

#### Scenario: File output without explicit format
- **WHEN** `--format` is not specified and `--output` is set to a file path
- **THEN** the `json` format is used

#### Scenario: Explicit format always wins
- **WHEN** `--format json` is specified
- **THEN** JSON format is used regardless of output destination

### Requirement: NO_COLOR and --no-color support
Color can be disabled via environment variable or flag.

#### Scenario: NO_COLOR environment variable
- **WHEN** the `NO_COLOR` environment variable is set (any value)
- **THEN** colors are disabled in text output

#### Scenario: --no-color flag
- **WHEN** `--no-color` flag is passed
- **THEN** colors are disabled in text output
