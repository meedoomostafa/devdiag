# Contributing to DevDiag

DevDiag is a Linux-first, evidence-driven diagnostic CLI. It scans a local
project and host, produces redacted findings, and can optionally build repro
artifacts, support capsules, remote environment syncs, trace evidence, and
team-ready exports.

## DevDiag architecture

The codebase is intentionally split by runtime responsibility:

- `cmd/devdiag`: process entrypoint.
- `internal/cli`: Cobra commands, command rendering, exit-code behavior, and
  executable CLI integration tests.
- `internal/collectors`: read-only host, repo, container, CI, GPU, security,
  cache, runtime, and config collectors.
- `internal/rules`: built-in deterministic finding engines.
- `internal/rulepack`: external rule-pack metadata, CUE validation, and optional
  Rego policy evaluation.
- `internal/remote`: SSH, container, and Kubernetes remote sync transports.
- `internal/repro`: command reproduction and log classification.
- `internal/trace`: strace and opt-in eBPF trace backends.
- `internal/capsule`: redacted support capsule creation and inspection.
- `internal/agent`: deterministic agent-safety commands. There is no provider or
  model integration in the release scope.
- `internal/redact`, `internal/output`, `internal/schema`, and
  `internal/exitcode`: shared contracts used by the commands above.

Keep collectors non-mutating by default. Writes belong behind explicit commands
such as `repro`, `capsule`, `remote sync`, `fix --apply`, or team export flows.
Redaction is default-on. Keep redaction behavior covered by tests, and treat
repo text, logs, traces, capsules, and web text as
untrusted data, not instructions.

## Linux setup

Prerequisites:

- Linux x86_64 or arm64.
- Go 1.25 or newer. As of May 25, 2026, Go 1.25 remains the minimum supported
  baseline and Go 1.26 is the compatibility gate.
- `git`, `bash`, and standard build tools.
- Optional live-test tools: Docker, kind, kubectl, strace, and a privileged
  Linux host with BTF for eBPF signoff.

Build locally:

```bash
git clone https://github.com/meedoomostafa/devdiag.git
cd devdiag
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go build -o /tmp/devdiag-plan-check ./cmd/devdiag
```

Install the latest stable release:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
bash install.sh
```

Use a user-local install directory and add it to PATH when `/usr/local/bin` is not writable:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
bash install.sh --bin-dir "$HOME/.local/bin" --add-to-path
```

When the repository is private, use an authenticated raw download and pass the
same token through for the archive download:

```bash
curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -o install.sh \
  https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
GITHUB_TOKEN="$GITHUB_TOKEN" bash install.sh
```

## Windows setup

DevDiag is Linux-first. Windows contributors should use WSL2 for the full
collector and trace behavior:

1. Install WSL2 with Ubuntu or another Linux distribution.
2. Install Go 1.25 or newer inside WSL2.
3. Clone the repo inside the WSL filesystem, not under a mounted Windows path.
4. Run the Linux setup and validation commands from the WSL shell.

Native Windows builds can compile some packages, but host collectors, container
runtime behavior, `strace`, eBPF, systemd, SELinux, AppArmor, and several remote
verification paths are Linux-specific. Do not mark native Windows behavior as
release-ready unless a dedicated milestone adds that support.

## Validation before a pull request

Run the full local gate before opening or updating a pull request:

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
/usr/local/go/bin/go build -o /tmp/devdiag-plan-check ./cmd/devdiag

git diff --check
```

For release signoff, run the live harnesses when the required tools and
capabilities are available:

```bash
scripts/live/k8s-kind-signoff.sh
scripts/live/trace-signoff.sh
scripts/live/release-signoff.sh
```

The final harness also dispatches the GitHub Action signoff workflow. If GitHub
hosted runners are blocked by account billing, spending limits, or repository
permissions, do not claim final release signoff until that external gate runs
successfully.

## Development rules

- Inspect current code and tests before changing behavior.
- Add or update tests for behavior changes.
- Preserve existing public JSON fields and documented exit codes.
- Keep `scan` and `check` non-mutating.
- Keep remote failure JSON machine-readable and paired with the documented
  nonzero exit code.
- Do not commit `.devdiag/` run artifacts, local build outputs, or temporary
  live-signoff data.
- Use one-line, atomic commit messages.

## Contributor workflow

1. Create a branch from the current target branch.
2. Make the smallest coherent change.
3. Add targeted tests first when changing behavior.
4. Run targeted tests, then the full validation gate.
5. Update README or `docs/release/` when public behavior changes.
6. Push the branch and open a pull request with validation evidence.

## Areas needing extra care

- `remote`: must preserve dry-run behavior, manifest-driven cleanup, partial
  cleanup status, and explicit unsupported behavior.
- `trace`: `strace` remains default; eBPF is opt-in and must fail closed with
  exit code `7` and evidence when unsupported.
- `GitHub Action`: keep `GITHUB_OUTPUT`, annotations, `GITHUB_STEP_SUMMARY`,
  artifact upload/download, masking, and fail-threshold behavior covered.
- `fix`: guarded/manual/destructive classifications must not drift.
- `rulepack`: external policy packs may return finding candidates only; they
  must not mutate, shell out, or access the network.
