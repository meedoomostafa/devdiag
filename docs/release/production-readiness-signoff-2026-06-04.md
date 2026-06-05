# Production Readiness Signoff Evidence

Date: 2026-06-04

This evidence records the local production-readiness pass for the current
working tree. It does not claim hosted GitHub Actions completion because the
current fixes are local and have not been pushed to a branch with a hosted run.

## Local Gates

| Gate | Result |
| --- | --- |
| `go test ./... -count=1` | pass |
| `go test -race ./internal/tui ./internal/app ./internal/cli -count=1` | pass |
| `go vet ./...` | pass |
| `go build -o /tmp/devdiag-production ./cmd/devdiag` | pass |
| `git diff --check` | pass |
| CLI smoke matrix | pass, 52 command paths |
| TUI non-TTY smoke | pass, `inspect .` exits 2 |
| TUI pseudo-TTY smoke | pass, quits cleanly with `q` |

Trace executable smoke was skipped because `strace` is not installed in this
environment. The `trace --help` command was covered by the CLI matrix.

## Fixes Validated

| Area | Evidence |
| --- | --- |
| Remote session cache | Full `go test ./... -count=1` passes after descriptive session IDs and cache identity validation fixes. |
| Kubernetes upload tests | Full suite passes after quoted upload command expectation alignment. |
| TUI progress polish | `internal/tui` tests cover spinner scheduling, default path, collector summary, running status, and partial status. |
| CI runtime-pin noise | `F-CI-PACKAGE-001` now groups matrix versions into one finding per setup action. |
| CI service noise | `F-CI-SERVICE-002` now requires CI service evidence before flagging local-only Compose services. |
| Missing scan path | `scan`, `check`, and `inspect` now reject missing/non-directory project paths with exit code 2. |

## Real-Project Scan Matrix

Binary: `/tmp/devdiag-production`

| Target | Exit | Findings | Collector status | Classification |
| --- | ---: | ---: | --- | --- |
| `/home/medo/Nexuq` | 0 | 7 | all ok | valid or intentionally suppressible |
| `/home/medo/FederatedTraining/server` | 3 | 7 | `compose_status` partial | valid project/env issue; no DevDiag noise found after fixes |
| `/home/medo/FederatedTraining/website` | 0 | 0 | all ok | clean |
| `/home/medo/FederatedTraining/worker` | 0 | 0 | all ok | clean |
| `/home/medo/Bosla/API` | 0 | 3 | all ok | valid or intentionally suppressible |
| `/home/medo/Bosla/BoslaPipeline` | 0 | 5 | all ok | valid or intentionally suppressible |
| `/home/medo/Bosla/bosla-ai-frontend` | 0 | 4 | all ok | valid or intentionally suppressible |

`/home/medo/FederatedTraining/Server` does not exist; the validated target is
`/home/medo/FederatedTraining/server`.

## Finding Classification

| Target | Finding IDs | Classification |
| --- | --- | --- |
| Nexuq | `F-ENV-001`, `F-CI-ENV-001`, `F-CI-COMMAND-001`, `F-CI-ENV-002`, `F-CI-SERVICE-002`, `F-RUNTIME-DECL-001` | valid environment/CI parity findings; service findings remain because CI declares services and local Compose has additional services |
| FederatedTraining/server | `F-ENV-001`, `F-ENV-002`, `F-CI-PACKAGE-001`, `F-CI-ENV-002`, `F-RUNTIME-DECL-001` | valid env/runtime findings; Compose partial is caused by required `POSTGRES_*` variables missing |
| FederatedTraining/website | none | clean |
| FederatedTraining/worker | none | clean |
| Bosla/API | `F-ENV-001`, `F-CI-PACKAGE-001`, `F-CI-ENV-002` | valid environment/runtime/CI parity findings |
| Bosla/BoslaPipeline | `F-ENV-001`, `F-CI-ENV-001`, `F-CI-PACKAGE-001`, `F-CI-ENV-002`, `F-RUNTIME-DECL-001` | valid environment/runtime/CI parity findings |
| Bosla/bosla-ai-frontend | `F-ENV-001`, `F-CI-PACKAGE-001`, `F-CI-COMMAND-001`, `F-CI-ENV-002` | valid environment/runtime/CI parity findings; command finding is intentionally suppressible if those CI commands are not meant to be documented locally |

No known invalid/noisy findings remain from this local pass.

## CLI Smoke Summary

The smoke matrix covered:

- root help and every top-level command help
- shell completions for bash, zsh, fish, and powershell
- scan formats: json, human, ndjson, markdown, github
- saved report consumers: `fix --list`, `issue template`, `team bundle`,
  `capsule create`, `capsule inspect`
- check commands: env, runtime, ci, containers, security
- agent commands: run, secret-redaction path, explain help, sandbox
- repro success and failure exit code 6
- invalid input paths for scan, check, inspect, and remote malformed targets

Result: `SMOKE_SUMMARY pass=52 fail=0`.

## Hosted GitHub Actions

Current hosted workflow state:

- `gh auth status`: authenticated with `repo` and `workflow` scopes.
- Workflows present and active: `ci`, `action live signoff`.
- Recent remote `ci` runs on `main` are old failures from 2026-05-25 to
  2026-05-29.

Deferred gate:

- Run `action-live-signoff.yml` and `ci.yml` on a pushed branch or PR that
  contains this exact diff.
- Verify uploaded artifact, annotations/summary, masking, and no-secret checks
  from the hosted run.

Until that hosted run completes successfully, this signoff is local-only and
DevDiag should not be called fully production-ready.
