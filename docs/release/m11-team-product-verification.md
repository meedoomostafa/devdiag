# M11 Team Product Layer Verification

Date: 2026-05-24

## Scope

This note records the local completion surface for Milestone 11. M11 is limited
to the open-source team workflow layer: shareable baseline config, deterministic
rule-pack metadata validation, issue-template generation, and machine-readable
capsule review output.

Deferred and not required for M11:

- SaaS dashboard.
- Paid rule-pack registry.
- Editor extensions.
- OPA/Rego or CUE policy execution. These are now tracked by M14.
- Provider-backed LLM or local model integration.

## Implemented Contract

- `devdiag.yaml` is the preferred shareable team baseline/config file.
- Legacy `.devdiag.yml` and `.devdiag.yaml` config files remain accepted.
- `.devdiag/` remains local artifact storage for saved runs and latest pointers.
- Config collection emits `devdiag_policy_fail_severity` evidence when
  `policy.fail_severity` is present.
- `policy.fail_severity` controls default `scan`/`check` exit thresholds unless
  an explicit `--fail-severity` flag is passed.
- `devdiag rules packs --format json` lists built-in deterministic rule packs.
- `devdiag rules validate <file> --format json` validates team rule-pack
  metadata before it is shared.
- `devdiag issue template --run-id <run-id>` generates an issue-ready Markdown
  body from a saved report.
- `devdiag issue template --run-id <run-id> --capsule <file> --format json`
  includes capsule validity, run ID, redaction status, file count, and review
  summary metadata.
- `devdiag capsule inspect <file> --format json` exposes stable review fields:
  `run_id`, `redaction_status`, `file_count`, and `review_summary`.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/collectors/config ./internal/rulepack ./internal/capsule ./internal/cli -run 'TestCollectorPrefersShareableDevDiagYAML|TestBuiltInPacks|TestValidatePack|TestRulesPacks|TestRulesValidate|TestIssueTemplate|TestCapsuleInspectJSONAfterReproCapsuleCreate' -count=1
```

## Acceptance Notes

- Rule-pack validation was metadata-only for M11. M14 owns CUE schema
  validation and optional Rego policy-pack execution.
- Issue templates use the default redaction engine unless the operator
  explicitly disables redaction with `--redact off`.
- Capsule inspect never extracts raw logs; it reads archive metadata and the
  manifest only.
