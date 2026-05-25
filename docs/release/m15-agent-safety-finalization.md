# M15 Agent Safety Finalization

Date: 2026-05-25

M15 finalizes the deterministic agent-safe surface. External model integrations
and generated model output are not part of the DevDiag release contract.

## Implemented Contract

- `devdiag agent explain <finding-id-or-path>` builds an agent-safe context.
- `devdiag agent run -- <cmd>` runs an operator-supplied command and reports
  redacted evidence.
- `devdiag agent sandbox --patch <patch> -- <cmd>` applies an operator-supplied
  patch in a temporary isolated copy and runs the operator-supplied command.
- Repository text, logs, traces, capsules, and command output are untrusted data.
- The prompt-injection classifier reports hostile text as evidence only.
- DevDiag never executes model-generated commands because there is no model
  provider surface.

## Public Interface

`agent explain` intentionally has no provider or model flags:

```bash
devdiag agent explain README.md --format json
```

Expected JSON includes:

- `schema_version`
- `generated_at`
- `root`
- `inputs`
- `findings`

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/agent ./internal/cli \
  -run 'TestBuildContext|TestClassifyPromptInjection|TestAgentExplainJSONMarksFileUntrustedAndReportsInjection|TestAgentRunJSONRedactsOutputAndReportsInjection|TestAgentSandboxAppliesPatchRunsCommandAndCleansUp|TestAgentSandboxPatchFailureJSON' \
  -count=1
```

Additional hygiene gate:

```bash
rg -n 'external-model-live-call-placeholder' README.md docs internal
```

Expected: no matches.
