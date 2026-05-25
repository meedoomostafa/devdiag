# M5 Fix Planner Verification

Date: 2026-05-24

## Scope

This note records verification of the safe fix planner. M5 counts complete for
the documented safe, guarded, manual, and blocked remediation model.

## Implemented Contract

The current fix planner now verifies these M5 behaviors locally:

- `devdiag scan` remains non-mutating unless `--save-report` is explicit.
- `fix --list` requires a saved report and points users to
  `devdiag scan --save-report` when no report exists.
- Safe `chmod-script` proposals execute only with `--apply` and write audit
  entries.
- Manual proposals refuse automatic application and write audit entries.
- Guarded proposals require fresh source data and an interactive TTY.
- `systemctl-daemon-reload` is guarded and was covered with fake-command PTY
  validation.
- `compose-up` is now a guarded proposal for non-running Compose services. It
  binds only validated `compose_service_<service>_status` evidence, runs through
  `docker compose --project-directory <repo> up -d <service>`, and exposes
  `docker compose --project-directory <repo> stop <service>` rollback metadata.
- `fix --templates --format json` exposes command, rollback, guarded risk text,
  blocked reason, and required evidence metadata so registry templates can be
  audited without applying them.
- `fix --apply` refuses to apply a finding with multiple proposals unless the
  operator selects one with `--hint <hint-id>`. The refusal renders the available
  proposals first and exits with unsafe-refused before any mutation.
- `fix --apply --hint <hint-id>` filters to one matching proposal before
  rendering or executing it. Unknown hints exit with invalid input and do not
  fall back to another proposal.
- Service-affecting actions remain guarded. The test suite proves command
  wiring and TTY confirmation with fake external commands instead of mutating
  real Docker Compose or systemd state during acceptance.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/fix -run 'TestPlannerResolveComposeUpGuardedWithRollback|TestPlannerSkipsGuardedComposeUpForInvalidServiceEvidence|TestRegistryClasses' -count=1
```

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/cli -run 'TestFixTemplatesJSONIncludesCommandRollbackAndRiskMetadata|TestFixListComposeUp_JSONIncludesGuardedRollback|TestFixApplyMultipleProposalsRequiresHint|TestFixApplyHintSelectsSingleProposal|TestFixApplyUnknownHintDoesNotApplyFallbackProposal' -count=1
```

## Future Hardening

Host-specific live apply runs against real external services remain optional
release hardening. They are not required for M5 counting because those paths are
intentionally guarded and require an interactive operator decision before
mutation.
