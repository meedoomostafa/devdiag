# M10 Agent Sandbox Verification

Date: 2026-05-24

## Scope

This note records local verification for the deterministic Milestone 10 agent
interceptor and sandbox. No provider-backed LLM is required for M10 completion.
Provider-backed explanations are tracked separately by M15.

## Implemented Contract

- `devdiag agent explain <finding-id-or-path>` builds an agent-safe context.
- Context inputs are explicitly marked `trust: "untrusted"`.
- File contents, repo text, logs, traces, and capsule-derived content are treated
  as untrusted data, not instructions.
- `devdiag agent run -- <cmd>` executes a command with timeout support, redacts
  stdout/stderr previews, and reports prompt-injection evidence.
- `devdiag agent sandbox --patch <patch> -- <cmd>` copies the current workspace
  into a temporary sandbox, applies the patch there, runs the command there, and
  removes the sandbox unless `--keep` is set.
- Patch application failures render machine-readable JSON and return the
  documented repro-failed exit code instead of running the requested command.
- The prompt-injection classifier reports obvious instruction-injection and
  secret-exfiltration text as evidence only. It never treats untrusted text as
  executable instruction.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/agent ./internal/cli -run 'TestBuildContext|TestClassifyPromptInjection|TestAgentExplainJSONMarksFileUntrustedAndReportsInjection|TestAgentRunJSONRedactsOutputAndReportsInjection|TestAgentSandboxAppliesPatchRunsCommandAndCleansUp|TestAgentSandboxPatchFailureJSON' -count=1
```

## Remaining M10 Gaps

Provider-backed model integration remained intentionally out of scope for M10.
M15 adds optional provider-backed explanations while preserving the same
untrusted-context schema and non-execution safety contract.
