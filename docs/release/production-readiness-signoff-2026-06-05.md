# DevDiag Production Readiness Signoff Evidence

Date: 2026-06-05

Branch: `codex/production-readiness-20260605`

Validated implementation commit: `7af5bc4563d067cef993589167e644d3ba5dadde`

This evidence file was committed after validation; the only post-validation
change is the documentation record itself.

Binary used for local executable validation: `/tmp/devdiag-production`

Status: `passed`

## Command Results and Exit Codes

| Gate | Exit | Evidence |
| --- | ---: | --- |
| `go test ./... -count=1` | 0 | Full package suite passed on the final tree. |
| `go test -race ./internal/tui ./internal/app ./internal/cli -count=1` | 0 | Race suite passed for the TUI, app orchestration, and CLI layers. |
| `go vet ./...` | 0 | No vet findings. |
| `go build -o /tmp/devdiag-production ./cmd/devdiag` | 0 | Production binary built successfully. |
| `git diff --check` | 0 | No whitespace or patch-format errors. |
| GitHub action tag verification | 0 | Latest release lines resolved through GitHub API: `actions/checkout@v6`, `actions/setup-go@v6`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`. |
| Hosted `ci` workflow | 0 | Run `27022701954`, success on Go 1.25 and Go 1.26. |
| Hosted `action live signoff` workflow | 0 | Run `27022707253`, success on Go 1.25 and Go 1.26. |

## Hosted GitHub Actions Evidence

Repository: `meedoomostafa/devdiag`

### CI

Run: <https://github.com/meedoomostafa/devdiag/actions/runs/27022701954>

Head SHA: `7af5bc4563d067cef993589167e644d3ba5dadde`

| Job | Job ID | Result | Covered steps |
| --- | ---: | --- | --- |
| `test (1.25)` | `79754565324` | success | checkout v6, setup-go v6, `go build ./cmd/devdiag`, `go test ./...`, `go vet ./...` |
| `test (1.26)` | `79754565477` | success | checkout v6, setup-go v6, `go build ./cmd/devdiag`, `go test ./...`, `go vet ./...` |

### Action Live Signoff

Run: <https://github.com/meedoomostafa/devdiag/actions/runs/27022707253>

Head SHA: `7af5bc4563d067cef993589167e644d3ba5dadde`

| Job | Job ID | Result | Covered steps |
| --- | ---: | --- | --- |
| `action signoff go 1.25` | `79754588030` | success | build `devdiag`, create fixture, run action without failing on findings, verify output/summary/local report, download artifact, verify artifact, run fail-threshold case, verify threshold behavior |
| `action signoff go 1.26` | `79754587973` | success | build `devdiag`, create fixture, run action without failing on findings, verify output/summary/local report, download artifact, verify artifact, run fail-threshold case, verify threshold behavior |

Hosted annotations were intentional fixture diagnostics plus the expected
nonzero threshold invocation under `continue-on-error`. The run completed with
overall `success`; no action runtime deprecation warning remained after the
version update.

## Artifact, Masking, and No-Secret Evidence

Hosted artifact metadata from run `27022707253`:

| Artifact | Artifact ID | Size | GitHub artifact digest |
| --- | ---: | ---: | --- |
| `devdiag-report-1.25` | `7439842982` | 1856 bytes | `sha256:c34fed04cad088746e2e89e56f04d03e005710cc5def93044322bd4d9f6bcff5` |
| `devdiag-report-1.26` | `7439846605` | 1854 bytes | `sha256:6e584d4f3430ebc01a01508b1c0686063d9b2a348c24f1455d08c75ac26fb6a4` |
| `devdiag-report-threshold-1.25` | `7439843669` | 1854 bytes | `sha256:f41edd8070a04d8308607182a267054d5efc14c76ff3a26b58712e9b8ad0b174` |
| `devdiag-report-threshold-1.26` | `7439847474` | 1854 bytes | `sha256:4afd10bda9b61f9615a38ad6dda426350d023af3c9ab30bd87d6294b3541b162` |

Downloaded JSON report hashes:

```text
1515a9083c43bfd8d3ae902affb50e3aec8680aea49f68608ec939d2d0845b6f  /tmp/devdiag-final-action-artifacts/devdiag-report-1.25/devdiag-report.json
25dc4d0c5e60ac1527c9d9d0d1f78618a21a3496e0493a7d43b5054497fe6d7e  /tmp/devdiag-final-action-artifacts/devdiag-report-1.26/devdiag-report.json
9f6daef2fa44d899675cc09fd23be8b1334906f401b56b337b42429f318a442f  /tmp/devdiag-final-action-artifacts/devdiag-report-threshold-1.25/devdiag-report.json
129c2ae9ad4be65c7c7a0c24865dcea22f5e4f0db21a92f3ef04988dfe2e0eb9  /tmp/devdiag-final-action-artifacts/devdiag-report-threshold-1.26/devdiag-report.json
```

Artifact verification:

| Check | Result |
| --- | --- |
| `jq -e '.schema_version and .collectors and .findings'` on every downloaded report | pass |
| `grep -R "secret123" /tmp/devdiag-final-action-artifacts` | exit 1, no raw secret found |
| `jq -e '.. \| strings \| select(contains("<redacted>"))'` on every downloaded report | pass |

## CLI Smoke Summary

Smoke artifact directory: `/tmp/devdiag-smoke-final.6RieQK`

Result: `pass=87 fail=0 skip=1`

The skipped item was `trace-strace-success` because `strace` is not installed
on this host. Trace still had fresh executable coverage through:

| Command | Exit | Result |
| --- | ---: | --- |
| `/tmp/devdiag-production trace --help` | 0 | help renders |
| `/tmp/devdiag-production trace --format json -- true` | 7 | reports `strace_not_found` without crashing |
| `/tmp/devdiag-production trace --backend ebpf --scope file,network --format json -- true` | 7 | reports `ebpf_capabilities_missing` with evidence |

The broader CLI smoke matrix covered root help, all top-level command help,
subcommand help, shell completions, config/rule validation, scan output formats,
saved report consumers, all `check` subcommands, `fix`, `agent`, `repro`,
`capsule`, `issue`, `team`, `doctor`, malformed remote target diagnostics,
non-TTY `inspect`, and secret-redaction paths.

## TUI Smoke Summary

| Case | Exit | Evidence |
| --- | ---: | --- |
| Normal PTY, `120x40` | 0 | Rendered `DevDiag Inspect`, collector counts, and finding rows; exited cleanly after `q`. |
| Tiny PTY, `30x8` | 0 | Rendered `Terminal too small`; exited cleanly after `q`. |
| Non-TTY inspect path | 2 | Covered by CLI smoke as the expected non-interactive diagnostic. |

The TUI remains read-only: normal rendering, tiny-terminal fallback, keyboard
quit, and non-TTY rejection were validated without mutating the target project.

## Real-Project Scan Matrix

Scan artifact directory: `/tmp/devdiag-real-projects.jgR8od`

| Target | Exit | Findings | Collector status summary | Classification |
| --- | ---: | ---: | --- | --- |
| `/home/medo/Nexuq` | 3 | 8 | `docker:unavailable`, `compose_status:partial`, `ci:ok`; other core collectors ok or host-unavailable | valid or intentionally suppressible |
| `/home/medo/FederatedTraining/Server` | n/a | n/a | path missing | uppercase path does not exist; lowercase target validated |
| `/home/medo/FederatedTraining/server` | 3 | 8 | `docker:unavailable`, `compose_status:partial`, `ci:ok`; other core collectors ok or host-unavailable | valid or intentionally suppressible |
| `/home/medo/FederatedTraining/website` | 0 | 0 | core collectors ok or host-unavailable | clean |
| `/home/medo/FederatedTraining/worker` | 0 | 0 | core collectors ok or host-unavailable | clean |
| `/home/medo/Bosla/API` | 3 | 4 | `docker:unavailable`, `compose_status:partial`, `ci:ok`; other core collectors ok or host-unavailable | valid or intentionally suppressible |
| `/home/medo/Bosla/BoslaPipeline` | 0 | 6 | `docker:unavailable`, `compose_status:ok`, `ci:ok`; other core collectors ok or host-unavailable | valid or intentionally suppressible |
| `/home/medo/Bosla/bosla-ai-frontend` | 0 | 5 | `docker:unavailable`, `compose_status:ok`, `ci:ok`; other core collectors ok or host-unavailable | valid or intentionally suppressible |

`systemd:unavailable` is a host capability status, not a project finding. Docker
findings are valid where the target has Docker/Compose signals and the current
host user cannot reach the Docker daemon/socket.

## Finding Classification

| Target | Finding IDs | Classification |
| --- | --- | --- |
| `/home/medo/Nexuq` | `F-CI-COMMAND-001`, `F-CI-ENV-001`, `F-CI-ENV-002`, `F-CI-SERVICE-002`, `F-DOCKER-002`, `F-ENV-001`, `F-RUNTIME-DECL-001` | Valid CI/env/runtime/service parity findings or intentionally suppressible command-doc parity. `F-DOCKER-002` is valid Docker socket access evidence. |
| `/home/medo/FederatedTraining/server` | `F-CI-ENV-002`, `F-CI-PACKAGE-001`, `F-DOCKER-002`, `F-ENV-001`, `F-ENV-002`, `F-RUNTIME-DECL-001` | Valid env/runtime/CI/package findings. `F-DOCKER-002` is valid Docker socket access evidence. |
| `/home/medo/FederatedTraining/website` | none | Clean. |
| `/home/medo/FederatedTraining/worker` | none | Clean. |
| `/home/medo/Bosla/API` | `F-CI-ENV-002`, `F-CI-PACKAGE-001`, `F-DOCKER-002`, `F-ENV-001` | Valid environment, CI package, and Docker socket access findings. |
| `/home/medo/Bosla/BoslaPipeline` | `F-CI-ENV-001`, `F-CI-ENV-002`, `F-CI-PACKAGE-001`, `F-DOCKER-002`, `F-ENV-001`, `F-RUNTIME-DECL-001` | Valid environment/runtime/CI parity findings. `F-DOCKER-002` is valid Docker socket access evidence. |
| `/home/medo/Bosla/bosla-ai-frontend` | `F-CI-COMMAND-001`, `F-CI-ENV-002`, `F-CI-PACKAGE-001`, `F-DOCKER-002`, `F-ENV-001` | Valid environment/runtime/CI/Docker findings; command-doc parity is intentionally suppressible if those CI commands are not part of local docs. |

No known invalid/noisy finding remains from the validated real-project matrix.

## Fixes Covered by This Signoff

| Area | Evidence |
| --- | --- |
| Remote session cache/session ID stability | `go test ./... -count=1` and remote session tests pass after descriptive session IDs, manifest validation, and cache identity validation. |
| Kubernetes upload command test mismatch | `internal/remote/transport/k8s` tests pass with the quoted fake-runner expectation. |
| TUI polish | Bubble Tea/Bubbles/Lip Gloss inspect UI is covered by unit tests and PTY smoke for normal and tiny terminals. |
| Detection quality/noise | CI runtime-pin grouping, CI service evidence gating, Docker-vs-Podman signal selection, and real-project matrix classification are covered by regression tests and scans. |
| Secret redaction | CLI smoke, repro regression, and hosted action artifact checks verify raw secret values do not leak. |
| GitHub Action readiness | Metadata contract tests, hosted signoff workflow, artifact download, report schema validation, summary output, annotations, and fail-threshold behavior all passed. |

## Remaining Explicitly Deferred Work

- `/home/medo/FederatedTraining/Server` is not a real path on this machine;
  `/home/medo/FederatedTraining/server` was validated instead.
- Live successful `strace` tracing was not run because `strace` is not installed.
  The unavailable path is validated, and deterministic trace tests are included
  in the full Go suite.
- The repository's optional live kind/eBPF signoff scripts require Docker,
  kind, kubectl, and/or privileged eBPF host access. Those infrastructure-only
  checks were not used as blockers for this CLI/TUI/CI/open-source readiness
  signoff.

There are no remaining DevDiag code, test, CLI, TUI, detection-quality, or
hosted-action blockers from the production-readiness plan.
