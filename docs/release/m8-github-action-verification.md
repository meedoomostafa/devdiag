# M8 GitHub Action Verification

Date: 2026-05-24

## Scope

This note records verification of the DevDiag composite GitHub Action. M8 counts
complete for the hardened metadata, annotation, artifact, severity-threshold,
Go-compatibility, and masking contract. Hosted runner UI review remains release
signoff evidence, not a milestone blocker.

## Docs Baseline

Current GitHub Actions docs confirm these packaging contracts:

- Action metadata is defined by `action.yml` or `action.yaml`, including inputs,
  outputs, and composite `runs` steps:
  https://docs.github.com/en/actions/reference/metadata-syntax-reference
- Workflow commands can emit annotations and set outputs via `GITHUB_OUTPUT`:
  https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
- Job summaries are appended through `GITHUB_STEP_SUMMARY`:
  https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary
- Workflow artifacts are uploaded with `actions/upload-artifact@v4`:
  https://docs.github.com/en/actions/tutorials/store-and-share-data
- Go release history shows Go 1.26.3 and Go 1.25.10 were both released on
  2026-05-07; DevDiag keeps Go 1.25 as the minimum baseline and gates Go 1.26
  compatibility before release:
  https://go.dev/doc/devel/release

## Implemented Action Contract

`action.yml` currently:

- Requires `devdiag` to be available on `PATH`.
- Runs `devdiag scan` in the requested output format, defaulting to GitHub
  annotations.
- Forces CI/local parity collection by default through `ci: 'true'`.
- Generates a JSON report at
  `$RUNNER_TEMP/devdiag-artifacts/devdiag-report.json`.
- Exposes `report-path` through `GITHUB_OUTPUT`.
- Uploads the JSON report with `actions/upload-artifact@v4` and `if: always()`.
- Writes a concise job summary through `GITHUB_STEP_SUMMARY` by default.
- Makes findings exit behavior configurable with `fail-on-findings`.
- Supports `fail-severity` so jobs can fail on `info`, `low`, `medium`, `high`,
  or `critical` findings, or use `off` to leave findings non-fatal while still
  failing on collector and command errors.
- Supports `mask-values` for registering additional literal values with
  GitHub `add-mask` before DevDiag output is emitted.

## Implemented CI/Local Config Contract

DevDiag now prefers `devdiag.yaml` and still accepts legacy `.devdiag.yml` or
`.devdiag.yaml` project config for CI/local env parity ignore profiles. The
supported config keys are:

```yaml
ci:
  env:
    ignore_missing_local:
      - CI_ONLY_SECRET
    ignore_missing_ci:
      - LOCAL_ONLY_DEVELOPMENT_KEY
policy:
  fail_severity: high
```

This keeps default CI/local parity checks strict while letting a project
explicitly suppress known, intentional env-key asymmetry:

- `ignore_missing_local` suppresses `F-CI-ENV-001` for selected CI env keys.
- `ignore_missing_ci` suppresses `F-CI-ENV-002` for selected local `.env` keys.
- The collector emits only key names, not values.
- `policy.fail_severity` controls the default scan/check findings exit
  threshold unless an explicit CLI flag is provided.
- Missing config is OK; malformed config is reported as a partial collector
  result.

## Local Equivalent Audit

Automated tests now parse `action.yml` and execute the composite shell body with
a fake `devdiag` binary. This validates:

- Composite metadata shape.
- Required inputs and output mapping.
- Forced `--ci` argument.
- Quoted path forwarding, including paths with spaces.
- JSON artifact creation.
- `GITHUB_OUTPUT` report-path output.
- `GITHUB_STEP_SUMMARY` summary output.
- `fail-on-findings: false` allows exit code `1`.
- `fail-severity` is passed through to both annotation and JSON artifact scans.
- `mask-values` emits GitHub `add-mask` workflow commands before the scans.
- The redaction input is forwarded to both scans, and the JSON artifact path is
  tested with a fake secret payload to prevent raw secret regressions.
- Non-finding failures such as exit code `3` still fail the action.
- The repository CI workflow runs both the Go 1.25 minimum baseline and Go 1.26
  compatibility gate through the `actions/setup-go` version matrix.

Targeted command:

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/cli -run 'TestGitHubAction' -count=1
```

Additional config-targeted commands:

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/collectors/config ./internal/rules -run 'TestCollector|TestM8Engine_ConfigIgnoresSelectedCIEnvParityKeys' -count=1
```

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/cli -run 'TestCheckCI_DevDiagConfigIgnoresConfiguredEnvParityKeys' -count=1
```

## Hosted Runner Signoff

A hosted GitHub Actions run or equivalent runner environment should still be
used before release to visually confirm annotation display and artifact
retention/download behavior. Local tests prove the composite action script,
metadata, environment-file usage, masking, and artifact-path contract.
