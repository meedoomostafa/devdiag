# M9 Live Verification

Date: 2026-05-24

This document records executable evidence for Milestone 9 remote environment sync.
It is intentionally conservative: target parsing and dry-run rendering do not count
as live remote support.

Note: this is the M9 historical signoff record. Kubernetes transport support was
deferred from M9 and is tracked in `docs/release/m12-k8s-remote-verification.md`.

## Current Status

M9 counts complete for SSH and container remote sync acceptance.

Kubernetes did not count as part of M9. K8s target parsing was accepted in M9,
but `kubectl` transport implementation was intentionally deferred to M12.

Implemented and verified:

- SSH target parsing.
- Container target parsing.
- Kubernetes target parsing.
- SSH remote `doctor`, `sync`, `enter`, `clean`, and `status` dry-run rendering.
- SSH remote status/clean behavior when no cached session exists.
- `remote doctor` returns exit code `1` when SSH or container probes produce
  high-severity findings while preserving machine-readable JSON output.
- Failed live `remote sync` upload renders JSON with `status: "failed"` and returns
  exit code `6` instead of silently succeeding at the process level.
- Unsafe `remote clean` manifests render JSON with `status: "refused"` and return
  exit code `5`; partial cleanup renders JSON with `status: "partial"` and
  returns exit code `3`.
- Historical M9 unsupported status for Kubernetes remote targets across
  `doctor`, `sync`, `enter`, `clean`, and `status`.
- `remote` SSH targets support explicit `--ssh-identity-file`,
  `--ssh-known-hosts-file`, and `--ssh-strict-host-key-checking` options for
  isolated or CI-provisioned SSH acceptance environments.
- Live-gated SSH verification covers doctor, dry-run sync, sync, status, enter
  planning, partial cleanup, and cleanup.
- Live-gated Docker container verification covers doctor, dry-run sync, sync,
  status, enter planning, partial cleanup, and cleanup.

Deferred from M9:

- Kubernetes remote doctor/sync/enter/clean/status implementation. See M12.

## Verification Commands

Executed in `/home/medo/myTools/DevDiag` with the rebuilt binary:

```bash
PATH=/usr/local/go/bin:$PATH /tmp/devdiag-goal-check remote doctor user@example.invalid --dry-run --format json
PATH=/usr/local/go/bin:$PATH /tmp/devdiag-goal-check remote sync user@example.invalid --dry-run --format json
PATH=/usr/local/go/bin:$PATH /tmp/devdiag-goal-check remote enter user@example.invalid --dry-run --format json
PATH=/usr/local/go/bin:$PATH /tmp/devdiag-goal-check remote clean user@example.invalid --dry-run --format json
PATH=/usr/local/go/bin:$PATH /tmp/devdiag-goal-check remote status user@example.invalid --format json
```

Observed result:

- JSON output rendered successfully.
- Dry-run commands did not upload files or open shells.
- Status/clean reported no cached session when no session existed.

The historical Kubernetes unsupported behavior was covered by automated CLI
tests during M9. Current K8s transport behavior is covered by the M12 release
verification document.

```bash
PATH=/usr/local/go/bin:$PATH GOCACHE=/tmp/devdiag-go-build GOMODCACHE=/tmp/devdiag-go-mod XDG_CACHE_HOME=/tmp/devdiag-cache /usr/local/go/bin/go test ./internal/cli
```

Expected behavior:

- `remote doctor user@example.invalid --format json` with a failing SSH probe
  returns exit code `1`, keeps stdout as valid JSON, and reports
  `F-REMOTE-001`.
- `remote doctor container:docker/missing --format json` with a missing container
  returns exit code `1`, keeps stdout as valid JSON, and reports
  `F-REMOTE-007`.
- `remote sync user@example.invalid --format json` with a failing SSH upload path
  returns exit code `6`, keeps stdout as valid JSON, and reports
  `status: "failed"`.
- `remote clean user@example.invalid --session <unsafe> --format json` with an
  unsafe cached root returns exit code `5`, keeps stdout as valid JSON, and
  reports `F-REMOTE-005`.
- `remote clean user@example.invalid --session <partial> --format json` with a
  failing cleanup command returns exit code `3`, keeps stdout as valid JSON, and
  reports `F-REMOTE-010`.
- For current behavior, run the K8s tests and live gate documented in
  `docs/release/m12-k8s-remote-verification.md`.

Live-gated SSH verification is available when an SSH target is explicitly
provided:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
DEVDIAG_LIVE_SSH_TARGET=<user@host[:port]> \
DEVDIAG_LIVE_SSH_IDENTITY_FILE=<identity-file> \
DEVDIAG_LIVE_SSH_KNOWN_HOSTS_FILE=<known-hosts-file> \
DEVDIAG_LIVE_SSH_STRICT_HOST_KEY_CHECKING=yes \
/usr/local/go/bin/go test ./internal/cli -run TestRemoteLiveSSHVerification -count=1 -v
```

Observed on 2026-05-24:

- A temporary local `sshd` was started on `127.0.0.1:22222` with temporary
  host/client keys and an isolated known-hosts file.
- The command above passed.
- The test verified live SSH `doctor`, `sync --dry-run`, `sync`, `status`,
  `enter --dry-run`, partial cleanup, and final cleanup.
- Temporary SSH files and the temporary sshd process were removed after the
  test.

Live-gated container verification is available when a container target is
explicitly provided:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
DEVDIAG_LIVE_CONTAINER_TARGET=container:docker/<container-name> \
/usr/local/go/bin/go test ./internal/cli -run TestRemoteLiveContainerVerification -count=1 -v
```

Observed on 2026-05-24:

- A disposable Docker container was started from the local `nginx:latest` image.
- The command above passed.
- The test verified live container `doctor`, `sync --dry-run`, `sync`,
  `status`, `enter --dry-run`, partial cleanup, and final cleanup.
- The disposable container was removed after the test.

## Environment Blockers

The current environment can prove SSH and Docker container support with explicit
temporary targets. Remaining live gaps:

- Podman `info` succeeds in rootless mode with `pasta`, SELinux enabled, and no
  running containers, but no live Podman container target was available during
  this verification pass.
- No Kubernetes cluster/context was provided.

Kubernetes remote support is no longer tracked against M9. M12 owns `kubectl`
transport implementation and live signoff.
