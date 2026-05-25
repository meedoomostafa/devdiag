# M4 Repro Capsule Verification

Date: 2026-05-21

## Scope

This note records local command-level verification for the repro runner and
support capsule. No known M4 local contract gap remains after this audit.

## Implemented Contract

The current repro and capsule commands now verify these M4 behaviors locally:

- `devdiag repro --format json -- <cmd>` persists a run directory under
  `.devdiag/runs/<run_id>/` when executed inside a controlled temporary project.
- Failed commands exit through the documented repro-failed code while still
  rendering machine-readable report JSON on stdout.
- Saved repro artifacts include `report.json`, `repro.json`,
  `logs/command.stdout.log`, and `logs/command.stderr.log`.
- Command arguments, stdout/stderr previews, classification excerpts, and
  timeline details are redacted before `repro.json` is persisted.
- Uppercase `KEY=value` log lines are redacted per line, while lowercase
  diagnostic fields such as `exit_code=1` keep useful evidence.
- `repro --format ndjson` emits redacted event-shaped records for repro
  timeline events, final command result, and findings instead of only emitting
  finding objects.
- `repro --format ndjson` flushes the redacted `repro_start` record before the
  child command exits, so consumers can observe command start in real time.
- Golden classifier fixtures now cover every documented M4 repro
  classification category: permission denied, missing file, address already in
  use, connection refused, runtime version failure, dependency resolver
  failure, and Compose interpolation/config failure.
- Runtime-version repro output now maps through the classifier and M1 rules to
  `F-REPRO-006` in command-level JSON reports.
- Capsules now include a redacted Markdown report at `report.md`.
- Capsules now include redaction provenance at
  `redaction/rules-applied.json`, including the active redaction status, rule
  names, and replacement token.
- `capsule create --run-id <run_id> --format json` packages the saved repro
  result plus redacted stdout/stderr command logs into the capsule archive.
- Capsule creation re-applies the current redaction profile to loaded report,
  repro, and command-log artifacts before packaging them.
- `capsule inspect <file> --format json` validates a generated capsule and
  returns metadata/file lists without exposing raw log contents.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/redact -run 'TestRedactString_MultilineEnvValues|TestRedactString_DoesNotRedactLowercaseDiagnostics|TestRedactString_EnvWithColon' -count=1
```

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/capsule ./internal/cli -run 'TestBuilder_IncludesMarkdownReportAndRedactionRules|TestReproCommand_PersistsRedactedRunArtifacts|TestReproCommand_NDJSONEmitsRedactedEvents|TestReproCommand_NDJSONFlushesStartBeforeCommandExit|TestCapsuleCreateAfterReproIncludesRedactedCommandLogs|TestCapsuleInspectJSONAfterReproCapsuleCreate' -count=1
```

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/repro/classifier ./internal/rules ./internal/cli -run 'TestClassifier_GoldenFixtures|TestClassifier_VersionNotMatched|TestM1Engine_ReproRules_RuntimeVersionFailure|TestM1Engine_ReproRules_SpecificClassificationSuppressesGeneric|TestM1Engine_ReproRules_AddressInUse|TestRulesListIncludesSpecificReproFindings|TestReproCommand_RuntimeVersionFailureFinding' -count=1
```

## Remaining M4 Gaps

No known M4-specific local contract gap remains. Broader live environment
validation for Docker, Podman, GPU, trace, hosted CI, and remote targets is
tracked under their own milestone sections because those paths depend on host
daemon, driver, runner, or target access.
