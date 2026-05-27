# DevDiag Inspect and App-Layer Migration Plan

## 1. Purpose

DevDiag should remain CLI-first and engine-first while adding an optional
terminal-native inspection workflow. The goal is not to build a GUI-like wrapper
around command output. The goal is to make the same diagnostic engine usable by:

```text
Core diagnostic engine
  -> CLI reports: human, json, ndjson, markdown, github
  -> TUI inspect: interactive findings explorer
```

The TUI must consume structured reports, findings, evidence, and progress events
directly. It must not parse human CLI text.

Preferred user-facing command:

```bash
devdiag inspect .
```

Optional compatibility or discoverability alias:

```bash
devdiag tui .
```

Plain `devdiag` should keep showing normal Cobra help for now. It must not
auto-open the TUI in the first implementation.

## 2. Current-State Analysis

### 2.1 Entrypoint and Command Layer

- `cmd/devdiag/main.go` is a thin process entrypoint that calls `cli.Execute()`.
- `internal/cli/root.go` owns the global Cobra command, global flags, flag
  validation, logger construction, redaction engine construction, renderer
  selection, color-mode resolution, and process exit-code translation.
- `internal/cli/shared.go` owns shared CLI helpers such as run ID generation,
  renderer selection, host-info extraction, fail-severity handling, and exit-code
  mapping from findings and collector statuses.

### 2.2 Scan Logic Location

`internal/cli/scan.go` currently contains business logic that should move behind
an application service:

- Resolve scan path.
- Detect repo signals for Docker, Podman, CI, and Python/ML.
- Build the default collector list.
- Conditionally add container, CI, GPU/CUDA/ML, Docker-GPU, cache, and rule-pack
  collectors.
- Run collectors through `collectors.Runner`.
- Build the normalized graph snapshot.
- Evaluate M1, M6, M8, and external rule-pack policies.
- Aggregate findings.
- Build `schema.Report`.
- Render redacted output.
- Optionally persist reports under `.devdiag/runs/<run-id>/report.json`.
- Return documented exit codes.

The extraction target is to move scan orchestration into `internal/app`, while
leaving CLI-specific concerns in `internal/cli`:

- Argument parsing.
- Flag validation.
- Output rendering.
- User-facing stderr logging.
- Exit-code mapping.
- Explicit artifact writes such as `--save-report`.

### 2.3 Other Cobra Commands With Business Logic

These commands also contain business logic and should be extracted only in
deliberate later slices:

- `internal/cli/check.go`: duplicates scan-like orchestration for domain-specific
  collectors and policy evaluation. This is the next extraction target after
  `scan`.
- `internal/cli/check_ci.go`, `check_gpu.go`, `check_cache.go`: domain-specific
  check entrypoints with collector/rule behavior.
- `internal/cli/repro.go`: command execution, repro artifact writing, log
  classification, and report creation.
- `internal/cli/trace.go`: trace runner orchestration, trace report generation,
  artifact persistence, and trace-specific exit codes.
- `internal/cli/fix.go`: saved-report resolution, fix planning, guarded/manual
  execution, audit logging, TTY confirmation, and renderer selection.
- `internal/cli/capsule.go`: support capsule creation and inspection workflows.
- `internal/cli/remote.go`: SSH/container/Kubernetes target handling, dry-run
  planning, sync, enter, clean, and status behavior.
- `internal/cli/agent.go`: deterministic agent-safe explain/run/sandbox flows.
- `internal/cli/issue.go` and `internal/cli/team.go`: saved-run handoff and team
  export workflows.
- `internal/cli/config.go` and `internal/cli/rules.go`: config/rule-pack
  validation and listing. These are lower-priority extraction targets because
  they are already mostly command-specific.

### 2.4 Packages Needing Extraction or Adjustment

- `internal/app`: new package for application services shared by CLI and TUI.
- `internal/collectors`: add optional runner observer hooks for progress events.
- `internal/schema`: add optional finding metadata fields for richer inspection
  without renaming existing JSON fields.
- `internal/cli`: keep Cobra wrappers, but make `scan`, then `check`, call app
  services instead of owning orchestration.
- `internal/tui`: new package for the `inspect` TUI model, update loop, and view.
- `internal/output`: remains the CLI/report rendering package. The TUI should not
  depend on human renderer text.
- `internal/capsule`: should be called directly by an app/report service when the
  TUI exposes explicit capsule creation.

## 3. Target Architecture

### 3.1 Package Shape

Target package layout:

```text
internal/app/
  scan.go        # Scan service and default scanner wiring
  check.go       # Later: domain check service shared by CLI and TUI
  events.go      # Event, EventType, EventSink, sink helpers
  report.go      # Saved report helpers shared by CLI and TUI
  commands.go    # Equivalent CLI command hint helpers

internal/tui/
  model.go       # TUI state model
  update.go      # Event/key handling
  view.go        # Finding-first layout
  filters.go     # Domain/severity/confidence/risk filters
  commands.go    # Command hint rendering/copy integration
```

### 3.2 Application Service API

The initial exported API should stay small and should return `*schema.Report`
directly. Do not introduce a `ScanResult` wrapper unless every call site uses
that wrapper consistently.

```go
package app

import (
    "context"

    "github.com/meedoomostafa/devdiag/internal/schema"
)

type ScanOptions struct {
    Path         string
    Profile      string
    RulePackPath string
    RedactLevel  string
    CI           bool
}

func Scan(ctx context.Context, opts ScanOptions, sink EventSink) (*schema.Report, error) {
    return NewScanner(DefaultScannerDeps()).Scan(ctx, opts, sink)
}
```

For testability and future extraction, the package should also have an internal
scanner type with injectable dependencies:

```go
type Scanner struct {
    CollectorFactory CollectorFactory
    Runner           CollectorRunner
    Engines          EngineFactory
    RunID            func() string
    Now              func() time.Time
}

func NewScanner(deps ScannerDeps) *Scanner

func (s *Scanner) Scan(ctx context.Context, opts ScanOptions, sink EventSink) (*schema.Report, error)
```

This avoids forcing `internal/app` tests to run real host, Docker, Podman,
network, GPU, or CI collectors.

Flag ownership rule:

- All scan behavior-affecting flags must move into `ScanOptions`. This includes
  path, `--ci`, `--profile`, `--rule-pack`, and future flags such as domain
  filters, deep mode, collector timeout, remote target, or trace attachment when
  those flags change collectors, policy evaluation, or report contents.
- `RedactLevel` belongs in `ScanOptions` because event sanitization and report
  redaction status depend on it.
- Pure presentation and process-control flags stay in `internal/cli`: `--format`,
  `--verbose`, `--debug`, `--color`, `--no-color`, `--fail-severity`, output
  writers, and the explicit artifact action `--save-report`.

### 3.3 Separation of Responsibilities

`internal/app.Scan` should own:

- Path normalization.
- Collector selection.
- Collector execution.
- Graph snapshot creation.
- Rule evaluation.
- Finding aggregation.
- Report construction.
- Structured progress events.

`internal/app.Scan` should not own:

- Cobra arguments or flags.
- Terminal rendering.
- JSON/NDJSON/human output formatting.
- Process exit codes.
- Hidden stderr logs.
- TUI keybindings or layout.
- Automatic mutation.

Redaction boundary:

- `app.Scan` may build an in-memory structured report for rule evaluation, but
  every external boundary must use the configured redaction policy.
- App events must never emit raw secrets. Event `Message` and `Error` strings must
  be sanitized before `Emit`, and `Err` must remain internal-only with
  `json:"-"`.
- Reports are redacted at render and save boundaries. This includes stdout/stderr
  renderers, saved `.devdiag/runs` reports, TUI display, support capsules, and any
  future event stream.
- If redaction is explicitly disabled, CLI/TUI surfaces must warn before showing or
  writing potentially sensitive data.

### 3.4 CLI as Thin Wrappers

After extraction, `internal/cli/scan.go` should become:

```text
parse Cobra args and flags
build app.ScanOptions
call app.Scan(ctx, opts, sink)
redact report for display
render selected output format
persist report if --save-report was requested
map findings/collector statuses to documented exit code
```

`internal/cli/check.go` should be migrated later to a matching `app.Check` API.
Until that migration, it can continue using existing orchestration to avoid mixing
too much behavior into the first extraction.

### 3.5 TUI as Another App Consumer

`devdiag inspect .` should:

```text
initialize TUI model
start app.Scan in a goroutine with an EventSink
render live progress from app events
render the final structured report
allow finding-first inspection and filtering
show exact equivalent CLI commands for actions
```

The TUI must never shell out to `devdiag scan` and parse its human output.

## 4. Event Model

Events are internal and experimental in the first implementation. They are for app
progress tests, future TUI progress, and internal wiring only. They are not a
public NDJSON compatibility contract yet. If events are later exposed as a public
stream, add `SchemaVersion`, document stability rules, and add golden output tests
before treating them as stable.

### 4.1 Event Types

The first typed event model should include:

```go
type EventType string

const (
    EventScanStarted      EventType = "scan_started"
    EventCollectorStarted EventType = "collector_started"
    EventCollectorDone    EventType = "collector_done"
    EventRuleEvaluated    EventType = "rule_evaluated"
    EventFindingAdded     EventType = "finding_added"
    EventScanCompleted    EventType = "scan_completed"
    EventScanFailed       EventType = "scan_failed"
)
```

### 4.2 Event Shape

Use explicit fields, but keep the contract internal until a versioned public event
schema is intentionally introduced:

```go
type Event struct {
    Type       EventType              `json:"type"`
    Timestamp  time.Time              `json:"timestamp"`
    RunID      string                 `json:"run_id,omitempty"`
    Path       string                 `json:"path,omitempty"`
    Domain     string                 `json:"domain,omitempty"`
    Collector  string                 `json:"collector,omitempty"`
    Status     schema.CollectorStatus `json:"status,omitempty"`
    RuleEngine string                 `json:"rule_engine,omitempty"`
    CheckID    string                 `json:"check_id,omitempty"`
    FindingID  string                 `json:"finding_id,omitempty"`
    Severity   schema.Severity        `json:"severity,omitempty"`
    Confidence float64                `json:"confidence,omitempty"`
    DurationMs int64                  `json:"duration_ms,omitempty"`
    Message    string                 `json:"message,omitempty"`
    Error      string                 `json:"error,omitempty"`
    Err        error                  `json:"-"`
}
```

Do not expose raw `error` directly in JSON or TUI text. Convert it to a sanitized,
redacted string before emission. Event data should contain collector names,
statuses, finding IDs, severity, confidence, and safe summaries, not raw command
output, raw env values, raw log lines, tokens, keys, or unredacted paths that match
secret rules.

### 4.3 Event Sink

```go
type EventSink interface {
    Emit(Event)
}

type EventSinkFunc func(Event)

func (f EventSinkFunc) Emit(e Event) { f(e) }
```

Provide sink helpers:

- `NoopSink` for CLI paths that do not need progress.
- `ChannelSink` for the TUI update loop.
- Optional `RecordingSink` for tests.

Because collectors run concurrently, sink implementations must be concurrency-safe
or app must wrap them with a small mutex-protected sink.

### 4.4 Collector Runner Observer

`internal/collectors.Runner` should add observer support so timeout events are
emitted when the runner returns a timeout result, not only when the underlying
collector goroutine eventually exits.

Proposed non-breaking shape:

```go
type Observer interface {
    CollectorStarted(name string)
    CollectorDone(result schema.CollectorResult, duration time.Duration)
}

func (r *Runner) RunWithObserver(ctx context.Context, collectors []Collector, observer Observer) []schema.CollectorResult
```

Existing `Run` should call `RunWithObserver(ctx, collectors, nil)` so current
collectors and tests continue to work.

## 5. Inspect View Model and Future Finding Metadata

Do not immediately add every inspection-oriented field to public `schema.Finding`.
The first `inspect` implementation should use the existing report model and build
an internal view model for TUI rendering. Promote fields to `schema.Finding` only
after they prove stable and useful across CLI, JSON, capsules, and team workflows.

The existing finding model already includes ID, title, severity, numeric
confidence, layers, symptom, evidence, likely causes, fixes, and fix hints. That
is enough for the first read-only inspect workflow.

Initial internal model:

```go
type InspectFinding struct {
    Finding          schema.Finding
    ConfidenceLabel  string
    Domain           string
    Target           string
    BlastRadius      string
    MutationRisk     string
    Reasoning        []string
    SuggestedCommands []CommandHint
    RelatedResources []RelatedResource
}

type CommandHint struct {
    Title        string
    Command      string
    Kind         string
    MutationRisk string
}

type RelatedResource struct {
    Kind  string
    Value string
}
```

Initial derivation strategy:

- Derive confidence label from existing numeric confidence:
  - high: `>= 0.85`
  - medium: `>= 0.60 && < 0.85`
  - low: `< 0.60`
- Derive domain from finding ID, layers, collector evidence, or an internal
  metadata map.
- Derive blast radius and mutation risk from internal finding metadata and fix
  hints, not from new public JSON fields.
- Derive reasoning from explicit rule text where available; otherwise show a
  conservative fallback based on evidence and likely causes.
- Generate suggested commands from a helper that only emits commands that exist in
  the current CLI.

Important command reality:

- Use existing commands first, such as `devdiag check containers . --verbose`.
- Do not show `devdiag scan . --domain containers --verbose` unless a real
  `scan --domain` flag is implemented later.

Future public schema promotion rules:

- Add optional JSON fields only; never rename existing public fields casually.
- Promote one small field group at a time, such as `domain` and `target` first,
  then `blast_radius` and `mutation_risk` later if they are stable.
- Add schema tests, JSON compatibility tests, and representative rule tests for
  every promoted field.
- Keep TUI-only labels and layout concepts in `internal/tui` or `internal/app`
  unless they are useful to machine consumers too.

## 6. Command Design

### 6.1 New Inspect Command

Add a new Cobra command:

```go
var inspectCmd = &cobra.Command{
    Use:     "inspect [path]",
    Aliases: []string{"tui"},
    Short:   "Interactively inspect ranked findings and evidence",
    Args:    cobra.MaximumNArgs(1),
    RunE:    runInspect,
}
```

Docs and README should prefer:

```bash
devdiag inspect .
```

The alias may support:

```bash
devdiag tui .
```

Do not list `tui` as the primary product command in docs unless user testing shows
that the alias is needed for discoverability.

### 6.2 Existing Commands

Keep these automation paths intact:

```bash
devdiag scan . --format human
devdiag scan . --format json
devdiag scan . --format ndjson
devdiag check containers . --verbose
devdiag repro -- npm test
devdiag fix F-PORT-001 --dry-run
devdiag capsule create
```

Do not make plain `devdiag` auto-open the TUI yet.

Do not remove `doctor self` in this migration. De-emphasize it in product language
and docs, but preserve compatibility.

## 7. TUI MVP

### 7.1 Scope

The first TUI should be read-only with respect to the project, host, containers,
remote targets, and services. Read-only means no host mutation, no project-file
mutation, no container mutation, and no remote-target mutation. Explicit local
artifact writes, such as saving a redacted report or creating a redacted capsule,
are allowed only after a direct user action.

MVP command:

```bash
devdiag inspect .
```

### 7.2 Finding-First Layout

The primary UI model should be:

```text
Critical findings
Warnings
Info
Passed checks collapsed by default
```

Domain views should be filters, not the main navigation model:

```text
domain: repo/env/docker/git/ports/ci/gpu/remote
severity: critical/high/medium/low/info
confidence: high/medium/low
target: local/remote/container
mutation risk: none/low/high
```

### 7.3 Finding Detail Fields

The detail panel should show:

- Title.
- Severity.
- Confidence label and numeric score.
- Domain.
- Target.
- Blast radius.
- Mutation risk.
- Evidence.
- Why DevDiag thinks this.
- Likely causes.
- Suggested next commands.
- Equivalent DevDiag command.
- Related checks.
- Related files, processes, ports, services, containers, or remote targets.

### 7.4 MVP Actions

Recommended MVP actions:

- Rerun scan.
- Toggle verbose evidence.
- Filter by domain, severity, confidence, target, and mutation risk.
- Save report if app/report persistence has been extracted.
- Create capsule if the existing capsule package can be called safely from the TUI
  without re-entering Cobra command logic.
- Show command hints for the selected finding or action.
- Copy command only if a safe terminal/clipboard implementation is already chosen;
  otherwise show the command and defer copy support.
- Quit.

Do not expose `fix --apply` from the TUI MVP. Fix proposals may be shown later as
commands, but mutation must remain a deliberate CLI workflow until a separate
guarded TUI fix design is reviewed.

### 7.5 Empty and Partial States

The TUI must handle:

- No findings.
- All collectors unavailable.
- Partial collectors.
- Collector timeout.
- Permission denied.
- Scan cancellation.
- Rule-pack validation failure.
- Non-interactive terminal or unsupported terminal.
- Small terminal size.
- Redaction disabled warning.

## 8. Migration Sequence

Documentation updates should happen inside the phase that changes public behavior.
Do not create a separate documentation-only phase that delays user-facing command
accuracy.

### Phase 1: Extract `app.Scan` and Events

Goal:

- Add `internal/app.Scan` with typed internal events.
- Keep `devdiag scan` behavior unchanged by not switching the CLI wrapper yet.
- Add tests around the app service and event lifecycle.

Files to add:

- `internal/app/events.go`
- `internal/app/scan.go`
- `internal/app/scan_test.go`
- `internal/app/events_test.go`

Files to modify:

- `internal/collectors/runner.go`
- `internal/collectors/runner_test.go`

Acceptance criteria:

- `app.Scan` returns `*schema.Report` directly.
- App tests can run with fake collectors and fake rule engines.
- Collector start/done/timeout events are emitted in tests.
- Event strings are sanitized before `Emit`.
- No Bubble Tea or TUI code is introduced in this phase.
- CLI output remains unchanged because the CLI has not switched to app yet.

### Phase 2: Make `scan` CLI Use `app.Scan`

Goal:

- Replace scan orchestration inside `internal/cli/scan.go` with a thin wrapper
  around `app.Scan`.
- Preserve behavior-equivalent CLI output, JSON fields, report contents, and exit
  codes.

Files to add or modify:

- `internal/cli/scan.go`
- `internal/cli/shared.go` only if helper ownership needs to move.
- `internal/app/report.go` if saved-report persistence is shared.
- `internal/app/commands.go` only for command-hint helpers that are needed by scan
  output or tests.
- `internal/cli/cli_test.go` for behavior-equivalence coverage.

Acceptance criteria:

- `devdiag scan` uses `app.Scan`.
- Existing formats remain valid: human, json, ndjson, markdown, github.
- Existing documented exit codes remain unchanged.
- `--save-report` remains explicit and writes a redacted report at the save
  boundary.
- Presentation flags remain in CLI; behavior-affecting scan flags are passed via
  `ScanOptions`.
- README or contributor docs are updated if public behavior changes.

### Phase 3: Add Minimal Read-Only `devdiag inspect`

Goal:

- Add the user-facing interactive command using the existing report model.
- Use an internal `InspectFinding` view model instead of adding new public finding
  fields immediately.
- Keep the first inspect workflow read-only and finding-first.

Files to add:

- `internal/cli/inspect.go`
- `internal/tui/model.go`
- `internal/tui/update.go`
- `internal/tui/view.go`
- `internal/tui/filters.go`
- `internal/tui/commands.go`
- `internal/tui/*_test.go`

Potential dependency to evaluate in this phase only:

- `github.com/charmbracelet/bubbletea`
- `github.com/charmbracelet/bubbles`
- `github.com/charmbracelet/lipgloss`

Acceptance criteria:

- `devdiag inspect .` opens a read-only finding-first workflow in a TTY.
- `devdiag tui .` works as an alias only if intentionally kept.
- Non-TTY invocation fails clearly or falls back to a concise message without
  affecting JSON-oriented commands.
- The TUI consumes `app.Scan` events and `schema.Report`, not CLI output.
- The detail view uses existing report fields plus internal derived fields.
- No fix apply path exists in TUI.
- README docs prefer `devdiag inspect .` and preserve `devdiag scan .` as the
  automation path.

### Phase 4: Add Richer Finding Metadata Gradually

Goal:

- Promote only stable inspection fields from the internal view model into public
  schema, one small group at a time.
- Keep JSON backward-compatible by adding optional fields only.

Files to modify as needed:

- `internal/schema/finding.go`
- `internal/rules/m1engine.go`
- `internal/rules/m6engine.go`
- `internal/rules/m8engine.go`
- `internal/trace/analyzer.go`
- Relevant schema, rule, and output tests.

Acceptance criteria:

- Existing required JSON fields remain present.
- New public fields are omitted when empty.
- New fields have representative rule tests and JSON compatibility tests.
- TUI continues to work if a finding lacks the new fields.

### Phase 5: Extract `check` Into `app.Check` Later

Goal:

- Centralize domain-specific check orchestration after scan and inspect have
  settled.
- Avoid blocking the inspect MVP on full check-command extraction.

Files to add or modify:

- `internal/app/check.go`
- `internal/app/check_test.go`
- `internal/cli/check.go`
- `internal/cli/check_ci.go`
- `internal/cli/check_gpu.go`
- `internal/cli/check_cache.go`

Acceptance criteria:

- `devdiag check <domain>` remains behavior-compatible.
- Domain-specific collector selection is centralized.
- Inspect command hints can reuse check/domain knowledge without duplicating
  collector lists.

## 9. Non-Goals

Do not include these in the first implementation:

- `fix --apply` from TUI.
- Automatic fix execution.
- Daemon mode.
- Background monitoring.
- Web dashboard.
- Plugin marketplace or plugin system.
- Auto-opening the TUI from plain `devdiag`.
- Parsing human CLI output to power the TUI.
- Replacing JSON/NDJSON/markdown/GitHub output modes.
- Broad redesign of remote, trace, repro, capsule, or agent commands.

## 10. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Scan behavior changes during extraction | Keep CLI tests, add app fake-dependency tests, compare representative JSON fields before/after. |
| Exit-code regressions | Leave exit-code mapping in `internal/cli/shared.go` first; test high findings, partial collectors, permission denied, and invalid input. |
| Redaction leaks through events | Redact event messages and error strings; do not emit raw command output in events. |
| Event ordering is nondeterministic | Treat collector events as concurrent; tests should require presence and valid lifecycle, not total ordering except scan started/completed. |
| Collector timeout event arrives late | Add runner observer hooks that emit done when `runOne` returns timeout. |
| App tests accidentally depend on host state | Use injectable fake collectors, fake runner, fake rule engines, deterministic run IDs, and deterministic clocks. |
| Premature public schema churn | Keep inspection-only fields in an internal view model first; promote optional JSON fields only after tests prove stability. |
| TUI dependency footprint grows | Add Bubble Tea dependencies only after app extraction; keep TUI isolated under `internal/tui`. |
| Non-TTY behavior surprises users | Keep `scan` as default automation path; make `inspect` require/expect TTY and fail clearly when unavailable. |
| Save report/capsule conflicts with read-only claim | Define read-only as no host/project/container mutation; require explicit artifact actions for writes. |
| Equivalent command hints become fictional | Generate hints from a small helper that only uses commands that actually exist. |

## 11. Validation Plan

### 11.1 Phase 1 Validation

Run targeted app and collector tests:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/app ./internal/collectors -count=1
```

Confirm:

- `app.Scan` returns a report with required top-level fields.
- Internal events include scan started, collector started, collector done,
  rule evaluated, finding added when applicable, and scan completed or failed.
- Event error strings are sanitized before emission.
- Runner timeout events are emitted when `runOne` returns a timeout result.
- No CLI output changes are expected in this phase.

### 11.2 Phase 2 Validation

Run CLI behavior-equivalence checks:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/cli ./internal/app ./internal/collectors -count=1

PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go build -o /tmp/devdiag-app-layer-check ./cmd/devdiag

/tmp/devdiag-app-layer-check scan . --format json --fail-severity off
/tmp/devdiag-app-layer-check scan . --format human --fail-severity off
/tmp/devdiag-app-layer-check scan . --format ndjson --fail-severity off
```

Confirm:

- JSON stdout has no stderr contamination.
- Human output still renders top findings.
- NDJSON remains one JSON object per line.
- Exit codes match documented thresholds.
- `--save-report` still writes only when explicitly requested and uses the
  configured redaction boundary.

### 11.3 Phase 3 Validation

Run TUI model tests without requiring a real terminal:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/tui ./internal/cli ./internal/app -count=1
```

Manual TTY smoke test:

```bash
/tmp/devdiag-app-layer-check inspect .
/tmp/devdiag-app-layer-check tui .
```

Confirm:

- Findings are primary navigation.
- Filters work.
- Progress events display during scan.
- Detail panel works using existing report fields and internal derived fields.
- Equivalent command hints are valid real commands.
- No mutation action exists.

### 11.4 Phase 4 Validation

Run schema/rule/output compatibility checks when public finding metadata is added:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/schema ./internal/rules ./internal/trace ./internal/output -count=1
```

Confirm:

- New fields are optional and omitted when empty.
- Existing JSON fields are unchanged.
- Representative findings include new metadata only after tests prove stability.

### 11.5 Phase 5 Validation

Run domain command checks after `app.Check` extraction:

```bash
/tmp/devdiag-app-layer-check check env . --format json --fail-severity off
/tmp/devdiag-app-layer-check check runtimes . --format json --fail-severity off
/tmp/devdiag-app-layer-check check containers . --format json --fail-severity off
/tmp/devdiag-app-layer-check check ci . --format json --fail-severity off
```

Confirm domain collector selection and findings remain equivalent.

### 11.6 Full Validation Gate

Before finalizing implementation:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./... -count=1

PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go vet ./...

PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go build -o /tmp/devdiag-final-check ./cmd/devdiag

git diff --check
```

## 12. Open Questions

Resolve these before coding the TUI phase, not necessarily before app extraction:

1. Should `devdiag tui` be a public alias, a hidden alias, or omitted until users
   ask for it?
2. Should report saving from the TUI write the same `.devdiag/runs/<run-id>` layout
   as `scan --save-report`, or should it ask for an explicit output path?
3. Should command copying use OSC 52, an optional clipboard dependency, or be
   deferred in favor of showing selectable command text?
4. Should `scan --domain` be added later, or should equivalent commands continue
   to use `check <domain>`?
5. Which `InspectFinding` fields are stable enough to promote to public
   `schema.Finding`, and should promoted metadata come from central rule metadata,
   individual rule engines, or a hybrid of metadata defaults plus rule-specific
   reasoning?
