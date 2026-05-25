# M14 Policy and Schema Verification

Date: 2026-05-25

M14 adds versioned CUE validation for team configuration and rule-pack metadata,
plus opt-in Rego evaluation for external deterministic policy packs. Built-in
Go rule engines remain authoritative for DevDiag's milestone rules.

## Scope

Implemented:

- `devdiag config validate [path] --format json`
- CUE-backed validation for `devdiag.yaml`
- CUE-backed validation for rule-pack metadata
- Registry-ready rule-pack metadata fields:
  - `publisher`
  - `license`
  - `homepage`
  - `compatibility.devdiag_min_version`
  - `tags`
- External rule-pack execution through `devdiag scan --rule-pack <file>`
- `engine: go` remains the default rule-pack engine
- `engine: rego` requires:
  - `entrypoint`
  - `policy_files`
- Rego policies receive the normalized scan snapshot as JSON input and may only
  return finding candidates.

Not implemented:

- OPA/Rego is not used for built-in milestone rules.
- External policy packs cannot mutate the repo, run shell commands, or perform
  network access.
- Hosted registry and SaaS policy distribution are still future product slices.

## Validation Behavior

`devdiag.yaml` validation accepts:

```yaml
schema_version: "1"
ci:
  env:
    ignore_missing_local: [API_KEY]
    ignore_missing_ci: [LOCAL_ONLY]
policy:
  fail_severity: medium
```

It rejects unknown fields and invalid severity thresholds. Read failures and
schema failures are machine-readable in JSON mode and return exit code `2`.

Rule-pack validation accepts:

```yaml
schema_version: "1"
id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files:
  - policy.rego
rules:
  - id: F-TEAM-001
    severity: high
publisher: Example Team
license: Apache-2.0
homepage: https://example.invalid/devdiag
compatibility:
  devdiag_min_version: "0.1.0"
tags: [team, ci]
```

It rejects:

- missing pack IDs or versions;
- empty rule IDs;
- duplicate rule IDs;
- invalid severities;
- unsupported engines;
- `engine: rego` without an entrypoint or policy files;
- `engine: go` with policy files or an entrypoint;
- absolute or parent-directory policy paths;
- unknown mutation or shell-execution metadata such as `command` or `mutates`;
- Rego policies using unsupported network/runtime builtins;
- Rego outputs that are not finding candidates.

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/configschema ./internal/collectors/config ./internal/rulepack ./internal/cli \
  -run 'TestValidateYAML|TestCollector|TestValidatePack|TestEvaluateRegoFile|TestConfigValidateJSON|TestScanRulePack' \
  -count=1
```

Expected:

- Valid `devdiag.yaml` files pass.
- Invalid `devdiag.yaml` files fail with JSON output and exit code `2`.
- The config collector reports invalid config as a partial collector result
  without mutating the repository.
- Valid Go and Rego rule packs pass schema validation.
- Invalid rule packs report deterministic validation errors.
- Duplicate rule IDs are rejected.
- Unsupported engines and unsafe policy paths are rejected.
- Mutation and shell-execution metadata is rejected by the schema.
- Rego network/runtime builtins are rejected.
- Invalid Rego output is rejected.
- `scan --rule-pack` emits deterministic finding candidates and a `rulepack`
  collector evidence block.

## Executable Smoke

Validate config:

```bash
devdiag config validate devdiag.yaml --format json
```

Evaluate an external Rego pack:

```bash
devdiag scan . --rule-pack team-rules.yaml --fail-severity critical --format json
```

`scan` remains non-mutating unless the operator also passes `--save-report`.
