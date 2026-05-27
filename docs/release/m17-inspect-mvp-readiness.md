# M17 Inspect MVP Readiness

Date: 2026-05-27

M17 adds `devdiag inspect .` as a minimal read-only terminal findings explorer.
It does not expand public schema, migrate `check`, add fix-apply, or introduce
mutation actions.

## Scope

Implemented:

- `devdiag inspect .` interactive findings explorer
- `devdiag tui .` as an alias only
- `internal/app.Scan` event streaming via `ChannelSink` and `safeEventSink`
- Bubble Tea model with two-panel layout (findings list + detail panel)
- derived internal view model (`InspectFinding`) from existing `schema.Finding`
- severity/confidence ranking, domain/target/blast-radius/mutation-risk derivation
- real command hints (`check ci`, `check containers`, `check security`, `check gpu`,
  `check cache`, `check ports`, `scan --verbose`, `fix --dry-run`)
- filter mode (`/`) with text search across ID, title, domain, symptom
- compact single-column fallback for terminals smaller than 60x12
- progress view during scan with collector status indicators
- help overlay (`?`) with navigation keybindings
- non-TTY rejection with exit code 2
- scan context cancellation on quit (`q`/`ctrl+c`) and rerun (`r`)
- lifecycle-safe event sink to prevent panic on closed channels

Not implemented:

- fix apply from TUI
- project/host/container/remote mutation inside TUI
- public schema.Finding metadata expansion
- `scan --domain` flag
- daemon mode
- web dashboard
- editor extension

## Architecture

```text
internal/cli/inspect.go    -> Cobra command, TTY check, scan options
internal/tui/model.go      -> InspectFinding view model, sorting
internal/tui/filters.go    -> severity/domain/confidence/mutation-risk/text filters
internal/tui/commands.go   -> real command hint derivation
internal/tui/update.go     -> Bubble Tea update loop, scan lifecycle
internal/tui/view.go       -> progress, findings, detail, help, compact views
```

## Safety Boundaries

- `inspect` is read-only. It does not apply fixes, edit files, restart services,
  or mutate containers, hosts, or remote targets.
- It consumes `app.Scan` events and the final `schema.Report` directly. It does
  not shell out to `devdiag scan`.
- `scan` remains the primary automation path. `inspect` is an optional
  interactive companion.
- There is no fix-apply path inside the TUI.

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/tui ./internal/cli ./internal/app \
  -count=1
```

With race detector:

```bash
/usr/local/go/bin/go test -race ./internal/tui ./internal/cli ./internal/app \
  -count=1
```

Expected:

- `inspect . < /dev/null` exits with code 2;
- `tui . < /dev/null` exits with code 2;
- TUI unit tests cover: confidence labels, domain derivation, filter matching,
  navigation, empty findings, scan error state, long evidence rendering,
  small-terminal compact view, no-mutation keybindings, safe event sink,
  quit-cancels-scan, rerun-cancels-previous-scan;
- CLI integration tests verify non-TTY rejection and help output;
- no race warnings;
- no goroutine leaks.

## Executable Smoke

In an interactive terminal:

```bash
devdiag inspect .
devdiag tui .
```

In a non-interactive terminal (should exit with code 2 and no control characters):

```bash
devdiag inspect . < /dev/null
devdiag tui . < /dev/null
```

After running inspect, confirm scan output is unchanged:

```bash
devdiag scan . --format json --fail-severity off
devdiag scan . --format ndjson --fail-severity off
```

Regression check for existing commands:

```bash
devdiag scan . --format human --fail-severity off
devdiag check containers . --verbose
devdiag fix --list
devdiag capsule create --dry-run
devdiag repro -- echo test
devdiag rules list --format json
```
