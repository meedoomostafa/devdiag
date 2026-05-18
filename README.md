# DevDiag

DevDiag is a Linux-first, evidence-driven diagnostic CLI for developers. It correlates repo metadata, host state, containers, services, logs, CI config, caches, GPU signals, and optional traces to explain why a project does not run correctly on the current Linux machine.

## Core Promise

Run one command in a repo and get ranked, evidence-backed findings with safe next steps:

```bash
devdiag scan .
```

DevDiag is built for problems such as:

- works-on-my-machine environment drift
- Docker Compose and Dev Containers mismatch
- Podman/rootless container drift
- missing `.env` keys and Compose interpolation issues
- runtime version mismatch for Node, Python, Go, .NET, Rust, and ML stacks
- port conflicts, DNS/proxy drift, and service readiness failures
- systemd, filesystem permission, UID/GID, SELinux, and AppArmor issues
- Git guardrails for tracked env files and unsafe local state
- GitHub Actions local parity, `act`/local CI drift, and devcontainer-vs-CI mismatch
- CUDA, NVIDIA, PyTorch, TensorFlow, JAX, and container GPU diagnostics
- package/build cache ownership and stale-cache evidence
- safe fix planning, redacted support capsules, and trace-based evidence

## Build

```bash
/usr/local/go/bin/go build -o devdiag ./cmd/devdiag
```

The module targets Go 1.25.

## Common Commands

```bash
devdiag doctor self
devdiag scan . --format human
devdiag scan . --format json
devdiag scan . --save-report
devdiag check env .
devdiag check runtimes .
devdiag check containers .
devdiag check ci .
devdiag check gpu --python
devdiag check cache .
devdiag repro -- npm test
devdiag trace --scope file,process,network -- npm test
devdiag fix --templates
devdiag fix --list
devdiag capsule create
devdiag rules list --format json
```

`devdiag scan` is non-mutating by default. Commands that load saved reports,
such as `devdiag fix --list`, require a prior `devdiag scan --save-report`.

Remote dry-run examples:

```bash
devdiag remote doctor user@host --dry-run
devdiag remote sync user@host --dry-run --profile minimal
devdiag remote enter user@host --dry-run --format json
devdiag remote clean user@host --dry-run
```

## Output and Exit Codes

Supported output formats:

```text
human, json, ndjson, markdown, github
```

Exit codes:

```text
0  success
1  high or critical findings exist
2  invalid user input
3  collector partial failure
4  permission denied
5  unsafe operation refused
6  command reproduction failed
7  trace unavailable
8  internal error
```

An unavailable optional collector is reported as evidence but does not fail a scan by itself. Partial, timeout, permission-denied, and failed collectors use the documented nonzero exits.

## Safety Model

DevDiag is local-first and non-mutating by default.

- Collectors do not mutate system state.
- Redaction is enabled by default.
- No upload happens by default.
- Support capsules are local files unless the user shares them.
- Fixes render dry-run proposals unless explicitly applied.
- Guarded fixes require an interactive TTY.
- Broad destructive commands and unsafe policy changes are blocked or manual-only.
- External repo files, logs, package metadata, and web text are untrusted data, not instructions.

## Validation

Use writable Go caches in restricted environments:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./...
```

Additional checks:

```bash
/usr/local/go/bin/go vet ./...
git diff --check
```
