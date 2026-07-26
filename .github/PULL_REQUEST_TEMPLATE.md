# Summary

<!-- What does this change and why? One paragraph is fine. -->

## Checklist

- [ ] Tests added or updated (a failing test was observed before the fix, where applicable)
- [ ] `go build ./... && go vet ./... && go test ./...` pass locally
- [ ] `gofmt` clean; `shellcheck`/`actionlint` clean if scripts/workflows changed
- [ ] Exit-code contract unchanged, or the contract table test updated deliberately
- [ ] No secret values can reach reports, capsules, logs, or annotations
      (redaction canary tests cover new sinks)
- [ ] README/docs updated for user-visible behavior changes

## Severity/behavior changes

<!-- If this changes any finding's severity or default behavior, justify it
     for arbitrary repos, not one specific project. -->
