# M7 Trace Verification

Date: 2026-05-24

## Scope

This note records verification for trace mode. M7 counts complete for the
current `strace` backend implementation. The eBPF backend is explicitly
deferred to the M13 hardening milestone.

Note: this is the M7 historical signoff record. Current eBPF hardening is
tracked in `docs/release/m13-trace-ebpf-verification.md`.

## Implemented Contract

The current trace command now has local CLI-level coverage for these behaviors:

- Missing `strace` returns machine-readable JSON, marks the trace collector
  `unavailable`, records `trace_unavailable_reason=strace_not_found`, and exits
  with trace-unavailable.
- Ptrace permission denial from `strace` returns machine-readable JSON, marks
  the collector `unavailable`, records
  `trace_unavailable_reason=ptrace_permission_denied`, and exits with
  trace-unavailable.
- A fake successful `strace` run persists both the report and the redacted
  `trace-result.json` artifact under `.devdiag/runs/<run_id>/`, plus the latest
  convenience trace artifact under `.devdiag/latest/`.
- A fake hung `strace` run returns a JSON report with collector status
  `timeout`, persists a redacted trace artifact with `timed_out` and `partial`
  set, and exits through the repro-failed path.
- Fake trace evidence now proves the CLI path from parsed syscall event to
  analyzer finding. A traced `EADDRINUSE` bind event produces
  `F-TRACE-NET-002` with `trace_bind_port` and `trace_errno` evidence.
- Historical `--backend ebpf` behavior returned machine-readable
  trace-unavailable diagnostics and did not pretend eBPF was implemented.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/cli -run 'TestTraceCommand_StracelessJSONReportsUnavailable|TestTraceCommand_PtraceDeniedJSONReportsUnavailable|TestTraceCommand_FakeStracePersistsReportAndTraceArtifact|TestTraceCommand_FakeStraceTimeoutReportsCollectorTimeout|TestTraceCommand_FakeStraceFindingReportsTraceFinding' -count=1
```

Live-gated real `strace` acceptance:

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  DEVDIAG_LIVE_M7_STRACE=1 \
  /usr/local/go/bin/go test ./internal/cli -run TestTraceCommand_LiveStraceJSONAcceptance -count=1 -v
```

Observed on 2026-05-24:

- `strace` was not installed on the local host, so live real-strace acceptance
  was not run.
- Deterministic fake-strace acceptance covers unavailable, ptrace-denied,
  successful artifact persistence, timeout, and trace-to-finding paths.

## Later Hardening

Run the live-gated real-strace acceptance on a host where `strace` is installed
and ptrace is allowed. eBPF backend hardening is owned by M13.
