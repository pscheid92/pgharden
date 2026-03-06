## ADDED Requirements

### Requirement: Mock DBQuerier for unit tests
A mock implementation of `checker.DBQuerier` that returns preconfigured results for given SQL queries.

#### Scenario: Query returns expected rows
- **WHEN** a test configures the mock with a SQL pattern and result set
- **THEN** calling `Query()` or `QueryRow()` with matching SQL returns those results

#### Scenario: Query returns an error
- **WHEN** a test configures the mock with a SQL pattern and an error
- **THEN** calling `Query()` or `QueryRow()` with matching SQL returns that error

### Requirement: Core package test coverage
Unit tests exist for the following packages with meaningful coverage of primary logic paths.

#### Scenario: checker package tests
- **WHEN** `go test ./internal/checker/...` is run
- **THEN** tests cover: registry (Register, All, Get, CompareCheckIDs), runner filtering (include, exclude, section), runner skip logic (version, superuser, filesystem, commands), and ShowSetting

#### Scenario: hba package tests
- **WHEN** `go test ./internal/hba/...` is run
- **THEN** tests cover: parseLine for all connection types (local, host, hostssl), include directive handling, auth method classification

#### Scenario: netmask package tests
- **WHEN** `go test ./internal/netmask/...` is run
- **THEN** tests cover: CIDR parsing, network size for IPv4 and IPv6, netmask-to-prefix conversion

#### Scenario: config package tests
- **WHEN** `go test ./internal/config/...` is run
- **THEN** tests cover: DefaultConfig values, LoadFile with valid YAML, profile application, ConnString with and without DSN

#### Scenario: report package tests
- **WHEN** `go test ./internal/report/...` is run
- **THEN** tests cover: Build summary counts (pass/fail/skip/manual), section grouping, JSON output validity
