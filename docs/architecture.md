# Architecture — Hexagonal (Ports & Adapters)

```
Dependency rule:  Domain ← Platform ← App ← Adapter ← CLI (main)

internal/
├── domain/              Pure types, interfaces, zero internal deps
│   ├── domain.go        Check, Environment, DBQuerier, CommandRunner,
│   │                    CheckResult, Severity, Status, HBAEntry, RunResult,
│   │                    SectionID, SortChecks
│   └── setting_check.go SettingCheck (reusable check helper)
│
├── platform/            Cross-cutting utilities
│   ├── config/          Config struct, DefaultConfig, LoadFile
│   ├── buildinfo/       Build version info
│   └── labels/          Check titles, descriptions, section names
│
├── app/                 Business logic (depends on domain + platform)
│   ├── scanner/         Scan() pipeline: checks → runner → report → exit code
│   ├── runner/          Runner — executes checks, enforces requirements
│   ├── checks/          registry + section1-8 check implementations
│   ├── hba/             HBA parser (file + SQL), auth method classification
│   └── report/          Report types + Build() — assembles RunResults
│
├── adapter/             Infrastructure (depends on domain + app)
│   ├── postgres/        pgx connection, privilege detection
│   ├── environment/     Detect() — probes PG for version, platform, etc.
│   └── output/          WriteText, WriteJSON, WriteHTML + HTML template
│
└── cli/                 Wiring layer — Cobra commands, flag registration
    ├── root.go          Execute(), registerFlags, flag validation
    ├── scan.go          Connector, Detector, ReportWriter interfaces, run()
    ├── output.go        cliReportWriter, resolveFormat(), writeReportTo()
    ├── exitcode.go      ExitError constant (runtime errors)
    └── version.go       version subcommand


═══════════════════════════════════════════════════════════════════════
                    INFRASTRUCTURE BOUNDARIES
═══════════════════════════════════════════════════════════════════════

① Connector        ② Detector         ③ ReportWriter
   interface           interface          interface

 Production:        Production:         Production:
   dbConnector        envDetector         cliReportWriter
   pgx connection     environment.Detect  file/stdout + color

 Test mock:          Test mock:          Test mock:
   mockConnector      mockDetector        bufferWriter
   returns error      returns pre-built   writes to bytes.Buffer
   or nil db          *Environment

④ DBQuerier        ⑤ fs.FS            ⑥ CommandRunner
   interface           interface           interface
                       (stdlib)

 Production:        Production:         Production:
   pgx.Conn            os.DirFS("/")       osCommandRunner
                                            wraps exec.Cmd

 Test mock:          Test mock:          Test mock:
   pgxmock             fstest.MapFS        mockCmd
   returns rows        returns files       returns output
   from memory         from memory         from map

 Used by:            Used by:            Used by:
   Check unit tests    Filesystem          Command check
   (section1-8)        check tests         unit tests
   + env detection     (section1,2,4)      (section1,2,5,6,8)


═══════════════════════════════════════════════════════════════════════
                    TEST PYRAMID
═══════════════════════════════════════════════════════════════════════

                    ┌───────────┐
                    │   E2E     │  Docker + real PG
                    │           │  integration_test.go
                  ┌─┴───────────┴─┐
                  │  Integration   │  CLI run() with real
                  │                │  Connector + Detector
                ┌─┴────────────────┴─┐
                │    Unit tests       │  checks + pgxmock/MapFS/mockCmd
                │                     │  scanner, runner, report, CLI
                └─────────────────────┘
```
