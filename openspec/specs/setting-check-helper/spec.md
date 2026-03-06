## ADDED Requirements

### Requirement: SettingCheck implements the Check interface
A `SettingCheck` struct must satisfy the `checker.Check` interface (`ID()`, `Requirements()`, `Run()`), allowing it to be registered and executed identically to hand-written checks.

#### Scenario: Registration and execution
- **WHEN** a `SettingCheck` is registered via `checker.Register()`
- **THEN** it appears in `checker.All()` and is executed by the runner like any other check

### Requirement: Equality comparison
The default comparator compares the queried setting value against an expected string.

#### Scenario: Setting matches expected value
- **WHEN** `SHOW <setting>` returns a value equal to `Expected`
- **THEN** the check returns `StatusPass` with a SUCCESS message

#### Scenario: Setting does not match expected value
- **WHEN** `SHOW <setting>` returns a value not equal to `Expected`
- **THEN** the check returns `StatusFail` with a FAILURE message including both actual and expected values

### Requirement: Contains comparison
When comparator is `contains`, the check passes if the setting value contains the expected substring.

#### Scenario: Setting contains expected substring
- **WHEN** `SHOW <setting>` returns a value containing `Expected`
- **THEN** the check returns `StatusPass`

### Requirement: One-of comparison
When comparator is `oneof`, the check passes if the setting value matches any of a comma-separated list in `Expected`.

#### Scenario: Setting matches one of the allowed values
- **WHEN** `SHOW <setting>` returns `"ddl"` and `Expected` is `"ddl,all"`
- **THEN** the check returns `StatusPass`

### Requirement: Permission denied handling
When querying a setting fails with a permission denied error, the check should skip gracefully.

#### Scenario: Insufficient privileges
- **WHEN** `SHOW <setting>` fails with permission denied
- **THEN** the check returns `StatusSkipped` with an appropriate skip reason
