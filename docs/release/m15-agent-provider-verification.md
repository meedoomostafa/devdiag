# M15 Agent Provider Verification

Date: 2026-05-25

M15 keeps deterministic agent explanation as the default and adds optional
provider-backed explanations for `openai` and `local`. Provider output is
explanation-only; DevDiag never executes model-generated commands.

## Scope

Implemented:

- `devdiag agent explain <input> --provider deterministic|openai|local --model <name>`
- provider abstraction under `internal/agent/provider`
- deterministic provider fallback for unavailable provider paths
- OpenAI Responses API adapter using `POST /v1/responses`
- local HTTP provider adapter through `DEVDIAG_LOCAL_AGENT_ENDPOINT`
- redaction before provider calls and after provider responses
- provider prompt construction that preserves untrusted-context markers
- JSON output fields:
  - `provider_requested`
  - `provider_used`
  - `model`
  - `explanation`
  - `provider_fallback`
  - `provider_notes`

Default behavior:

- `agent explain` uses `--provider deterministic` unless explicitly changed.
- `--provider openai` requires `OPENAI_API_KEY` and either `--model` or
  `DEVDIAG_OPENAI_MODEL`.
- `DEVDIAG_OPENAI_BASE_URL` may override the default
  `https://api.openai.com/v1/responses` endpoint for tests or compatible
  gateways.
- `--provider local` requires `DEVDIAG_LOCAL_AGENT_ENDPOINT`; model selection
  may come from `--model` or `DEVDIAG_LOCAL_AGENT_MODEL`.
- unavailable providers return deterministic explanation JSON with a note
  rather than an internal error.

## Safety Contract

Provider prompts include:

- repository text, logs, traces, and capsules as untrusted data only;
- `trust: "untrusted"` markers from the agent context schema;
- an explicit instruction that hostile untrusted text is evidence only;
- an explicit instruction to never execute commands or request secrets.

Provider responses are redacted before rendering. DevDiag does not parse
provider responses as commands, patches, or instructions.

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/agent ./internal/agent/provider ./internal/cli \
  -run 'TestBuildContext|TestClassifyPromptInjection|TestExplain|TestAgentExplain' \
  -count=1
```

Expected:

- deterministic context building keeps inputs untrusted and redacted;
- prompt-injection fixtures produce evidence findings;
- OpenAI provider unavailability falls back to deterministic output;
- local provider unavailability falls back to deterministic output;
- OpenAI outbound payloads do not include raw secrets;
- OpenAI inbound responses are redacted before rendering;
- provider prompts preserve untrusted markers and non-execution instructions;
- `agent explain --provider openai --model <name> --format json` exits `0`
  with deterministic fallback when `OPENAI_API_KEY` is absent.

## Executable Smoke

Offline fallback:

```bash
env -u OPENAI_API_KEY \
devdiag agent explain README.md --provider openai --model gpt-test --format json
```

Expected output includes:

- `"provider_requested": "openai"`
- `"provider_used": "deterministic"`
- `"provider_fallback": true`
- an `OPENAI_API_KEY` note

Optional live OpenAI provider smoke:

```bash
OPENAI_API_KEY=<redacted> \
devdiag agent explain README.md --provider openai --model <model> --format json
```

Optional local provider smoke:

```bash
DEVDIAG_LOCAL_AGENT_ENDPOINT=http://127.0.0.1:11434/devdiag/explain \
devdiag agent explain README.md --provider local --model local-model --format json
```

Live provider signoff is optional; M15 is accepted when offline deterministic
fallback, redaction, and untrusted-context handling pass.
