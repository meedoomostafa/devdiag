# DevDiag

DevDiag is a Linux-first, evidence-driven diagnostic CLI for developers. It correlates repo metadata, host state, containers, services, logs, CI config, caches, GPU signals, and optional traces to explain why a project does not run correctly on the current Linux machine.

## Core Promise

Run one command in a repo and get ranked, evidence-backed findings with safe next steps:

```bash
devdiag scan .
```

For an interactive exploration of findings and evidence:

```bash
devdiag inspect .
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

## Command Philosophy

```text
scan    -> produce reports (automation, scripts, CI)
inspect -> interactively explore findings and evidence (read-only TUI)
check   -> targeted domain checks with verbose evidence
fix     -> deliberate dry-run and apply workflow outside the TUI
```

- `scan` is the primary automation path. It writes nothing unless `--save-report` is passed.
- `inspect` is an optional interactive workflow. It consumes the same `app.Scan` events and `schema.Report` as the CLI, but never shells out to `devdiag scan`.
- `check` is for deep domain investigation (containers, CI, GPU, security, etc.).
- `fix` is separate and explicit. There is no fix-apply path inside the TUI.

Plain `devdiag` shows normal Cobra help and does not auto-open the TUI.

## Build

```bash
/usr/local/go/bin/go build -o devdiag ./cmd/devdiag
```

The module targets Go 1.25 as the minimum supported baseline. CI also gates Go
1.26 compatibility before release.

## Install

Install the latest stable release:

```bash
curl -fsSL https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh | bash
```

The installer supports Linux distributions with Bash, `tar`, `curl` or `wget`,
and Go 1.25 or newer. It installs to `/usr/local/bin` when writable and falls
back to `~/.local/bin` otherwise.

Useful installer options:

```bash
# Install to a user-local directory.
curl -fsSL -o install.sh https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
bash install.sh --bin-dir "$HOME/.local/bin"

# Preview the detected archive, Go version, and install directory.
curl -fsSL -o install.sh https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
bash install.sh --dry-run

# Install another Git ref for testing.
DEVDIAG_INSTALL_VERSION=main bash scripts/install.sh --dry-run
```

For private repository installs, pass an authenticated GitHub token so the
installer can fetch the source archive:

```bash
curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -o install.sh \
  https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
GITHUB_TOKEN="$GITHUB_TOKEN" bash install.sh
```

## Common Commands

```bash
devdiag doctor self
devdiag scan . --format human
devdiag scan . --format json
devdiag scan . --format ndjson
devdiag scan . --ci
devdiag scan . --verbose
devdiag scan . --save-report
devdiag inspect .
devdiag tui .                       # alias for inspect
devdiag check env . --verbose
devdiag check runtimes . --verbose
devdiag check containers . --verbose
devdiag check containers --gpu
devdiag check security . --verbose
devdiag check ci .
devdiag check gpu --python
devdiag check cache .
devdiag repro -- npm test
devdiag repro --format ndjson -- npm test
devdiag trace --scope file,process,network -- npm test
devdiag trace --backend ebpf --scope file,process,network -- npm test
devdiag fix --templates
devdiag fix --list
devdiag capsule create
devdiag capsule inspect support-run.devdiag.tgz --format json
devdiag rules list --format json
devdiag rules packs --format json
devdiag rules validate team-rules.yaml --format json
devdiag issue template --run-id <run-id> --format markdown
```

`devdiag scan` is non-mutating by default. Commands that load saved reports,
such as `devdiag fix --list`, require a prior `devdiag scan --save-report`.

## Project Config

DevDiag prefers a shareable `devdiag.yaml` file for team baselines and policy
settings. Legacy `.devdiag.yml` and `.devdiag.yaml` files are still read for
compatibility. The `.devdiag/` directory remains reserved for local run
artifacts and should not be used as the shareable team config.

```yaml
policy:
  fail_severity: high
ci:
  env:
    ignore_missing_local:
      - CI_ONLY_SECRET
    ignore_missing_ci:
      - LOCAL_ONLY_DEVELOPMENT_KEY
```

`ignore_missing_local` suppresses `F-CI-ENV-001` for CI variables that should
not appear in local env files. `ignore_missing_ci` suppresses `F-CI-ENV-002` for
local-only variables that should not appear in CI.

`policy.fail_severity` sets the default findings exit-code threshold for
`scan` and `check` commands when `--fail-severity` is not passed. Explicit CLI
flags always win, and invalid config values are reported as partial collector
results.

Team rule-pack metadata can be inspected locally before it is shared:

```bash
devdiag config validate devdiag.yaml --format json
devdiag rules packs --format json
devdiag rules validate team-rules.yaml --format json
devdiag scan . --rule-pack team-rules.yaml --format json
```

Rule packs default to `engine: go` for built-in metadata. External
`engine: rego` packs must declare `entrypoint` and `policy_files`; policies
receive the normalized scan snapshot and may only return finding candidates.

Saved runs can generate issue-ready handoff text and optional capsule metadata:

```bash
devdiag scan . --save-report
devdiag capsule create --run-id <run-id>
devdiag issue template --run-id <run-id> --capsule support-<run-id>.devdiag.tgz --format json
devdiag team bundle --run-id <run-id> --format json
```

`team bundle` is a local export surface for future hosted dashboards or editor
extensions. It includes saved report metadata, optional capsule metadata,
built-in rule-pack metadata, stable output names, documented exit codes, and a
redacted issue-template body.

Remote dry-run examples:

```bash
devdiag remote doctor user@host --dry-run
devdiag remote sync user@host --dry-run --profile minimal
devdiag remote enter user@host --dry-run --format json
devdiag remote clean user@host --dry-run
devdiag remote doctor k8s:default/api-pod --dry-run --format json
devdiag remote sync k8s:prod/default/api-pod --k8s-container app --dry-run --format json
devdiag agent explain F-PORT-001 --format json
devdiag agent run -- npm test
devdiag agent sandbox --patch fix.patch -- npm test
```

SSH remote commands also accept explicit OpenSSH client options for release
verification or CI-provisioned targets:

```bash
devdiag remote doctor user@host \
  --ssh-identity-file /path/to/key \
  --ssh-known-hosts-file /path/to/known_hosts \
  --ssh-strict-host-key-checking yes
```

Kubernetes remote commands use `kubectl exec` with targets in
`k8s:namespace/pod` or `k8s:context/namespace/pod` form. Multi-container pods
can be selected with `--k8s-container <name>`. Remote files are staged under
`/tmp/devdiag-remote/<session>` and remain manifest-cleanable through
`devdiag remote clean`.

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
- `inspect` is read-only. It does not apply fixes, edit files, restart services,
  or mutate containers, hosts, or remote targets.
- Redaction is enabled by default.
- No upload happens by default.
- Support capsules are local files unless the user shares them.
- Repro command args, stdout/stderr previews, command logs, and capsule entries
  are redacted before persistence by default.
- Capsules include `report.md`, `findings.json`, snapshot JSON, redacted command
  logs when available, and `redaction/rules-applied.json`.
- Fixes render dry-run proposals unless explicitly applied.
- Guarded fixes require an interactive TTY.
- Guarded fix templates expose risk text and rollback metadata when available.
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

### Manual Inspect Verification

When running in a TTY:

```bash
devdiag inspect .
devdiag tui .
```

When running without a TTY (should fail cleanly with exit code 2):

```bash
devdiag inspect . < /dev/null
devdiag tui . < /dev/null
```

After using `inspect`, confirm `scan` output remains unchanged:

```bash
devdiag scan . --format json --fail-severity off
devdiag scan . --format ndjson --fail-severity off
```

## GitHub Action

The repository includes a composite action in `action.yml`. The action expects a
`devdiag` binary to already be available on `PATH`, then emits GitHub
annotations and uploads `devdiag-report` as a JSON artifact.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-go@v5
    with:
      go-version: '1.25'
  - run: |
      mkdir -p "$RUNNER_TEMP/bin"
      go build -o "$RUNNER_TEMP/bin/devdiag" ./cmd/devdiag
      echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"
  - uses: ./
    with:
      path: .
      format: github
      ci: 'true'
      fail-on-findings: 'true'
      fail-severity: high
```

Set `fail-on-findings: 'false'` to keep JSON artifact and annotation generation
without failing the job for DevDiag exit code `1`. Other nonzero exits still
fail the action. Use `fail-severity` to raise or lower the findings threshold;
supported values are `off`, `info`, `low`, `medium`, `high`, and `critical`.
