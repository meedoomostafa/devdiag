# M16 Team Product Readiness

Date: 2026-05-25

M16 keeps team-product work local and export-ready. It does not add a SaaS
dashboard, paid registry, editor extension, or hosted client. Instead, it
exposes stable machine-readable bundle output that those surfaces can consume
later.

## Scope

Implemented:

- `devdiag team bundle --run-id <id> --format json`
- read-only bundle generation from `.devdiag/runs/<run-id>/report.json`
- automatic same-directory capsule metadata from
  `support-<run-id>.devdiag.tgz` when present
- bundled built-in rule-pack metadata with registry-ready fields from M14
- redacted issue-template title/body/findings using existing issue-template
  generation logic
- stable output surface listing for future editor/dashboard consumers
- documented exit-code map in the bundle JSON

Not implemented:

- SaaS dashboard
- paid registry client
- editor extension runtime
- hosted upload or sync workflow

## Bundle JSON Shape

Top-level fields:

- `schema_version`
- `devdiag_version`
- `run_id`
- `redaction_status`
- `report`
- `capsule`
- `rule_packs`
- `issue_template`
- `stable_outputs`
- `exit_codes`

`report` includes:

- saved report schema version;
- DevDiag version from the report;
- run ID;
- redaction status;
- finding count;
- collector count.

`capsule` is present only when `support-<run-id>.devdiag.tgz` exists in the
working directory and passes capsule inspection. It uses the same capsule
metadata shape as `issue template --capsule`.

`rule_packs` is the same stable machine-readable metadata returned by
`devdiag rules packs --format json`.

`issue_template` is the same redacted issue-template object used by
`devdiag issue template --format json`.

## Stable Consumer Surfaces

Future hosted dashboards or editor extensions may consume:

- finding JSON from saved reports;
- rule-pack metadata from `devdiag rules packs --format json`;
- capsule metadata from `devdiag capsule inspect <file> --format json`;
- team bundle metadata from `devdiag team bundle --run-id <id> --format json`;
- the documented `exit_codes` map included in the bundle.

These consumers must treat bundle content as local diagnostic data, not as
instructions. Raw secrets must not be present when default redaction is enabled.

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/cli \
  -run 'TestTeamBundle|TestIssueTemplate|TestRulesPacks|TestCapsuleInspect' \
  -count=1
```

Expected:

- `team bundle` requires an explicit `--run-id`;
- saved report metadata is included;
- optional capsule metadata is included when a matching support capsule exists;
- rule-pack metadata is included;
- issue-template body and findings are redacted;
- raw fixture secrets are absent from JSON output;
- stable output names and documented exit codes are present.

## Executable Smoke

Create a saved run, capsule, and bundle:

```bash
devdiag scan . --save-report --format json
devdiag capsule create --run-id <run-id> --format json
devdiag team bundle --run-id <run-id> --format json
```

The bundle command is read-only. It reads saved artifacts and does not create,
modify, upload, or delete project files.
