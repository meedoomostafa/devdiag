# M13 Trace and eBPF Verification

Date: 2026-05-25

M13 keeps `strace` as the default trace backend and hardens the opt-in eBPF
backend. Unsupported eBPF environments fail closed with machine-readable JSON,
`trace_unavailable=true`, and exit code `7`.

## Scope

Implemented:

- `devdiag trace --backend strace` remains the default backend.
- `devdiag trace --backend ebpf` performs strict capability checks before any
  tracepoint attachment.
- eBPF capability evidence is emitted into collector evidence and
  `trace-result.json`.
- Linux eBPF support checks require:
  - BTF at `/sys/kernel/btf/vmlinux`;
  - `CAP_BPF` plus `CAP_PERFMON`, or `CAP_SYS_ADMIN`;
  - tracepoint program type availability from `github.com/cilium/ebpf/features`.
- The Linux eBPF backend attaches a minimal `github.com/cilium/ebpf` tracepoint
  program only to the explicit tracepoints needed for requested scopes.
- eBPF event adapters filter to the traced process tree before mapping records
  to the existing trace analyzer schema.

Not claimed:

- Full kernel-side syscall argument decoding is still a hardening follow-up.
  The backend does not fabricate events when no decoded eBPF records are
  available.

## eBPF Evidence

The trace collector emits:

- `trace_backend=ebpf`
- `trace_event_count=<n>`
- `trace_unavailable_reason=<reason>` when unavailable
- `ebpf_btf=present|missing`
- `ebpf_cap_eff=<hex>`
- `ebpf_cap_bpf=true|false`
- `ebpf_cap_perfmon=true|false`
- `ebpf_cap_sys_admin=true|false`
- `ebpf_tracepoint_program_type=available|unavailable`
- `ebpf_tracepoints_attached=<comma-separated tracepoints>` when attachment
  succeeds
- `ebpf_tracepoint_link_count=<n>` when attachment succeeds

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/trace ./internal/cli \
  -run 'TestCheckEBPFSupportReportsMissingBTFAndCapabilities|TestCheckEBPFSupportReportsFeatureProbeFailure|TestEBPFTracepointsAreScoped|TestEBPFRecordsMapToExistingFindingsAndFilterProcessTree|TestTraceCommand_EBPFBackendUnavailableDiagnostic|TestTraceCommand_EBPFBackendUnavailableJSONIncludesEvidence|TestTraceCommand_LiveStraceJSONAcceptance|TestTraceCommand_LiveEBPFJSONAcceptance' \
  -count=1
```

Expected:

- Missing BTF or required capabilities make eBPF unavailable.
- Tracepoint program-type probe failures make eBPF unavailable.
- eBPF tracepoints are selected only for requested scopes.
- Fake eBPF records from unrelated PIDs are filtered out.
- Fake eBPF records map to existing analyzer finding IDs.
- CLI JSON output includes backend, event count, unavailable reason, and
  capability evidence.
- Live `strace` acceptance is skipped unless `DEVDIAG_LIVE_M7_STRACE=1`.
- Live eBPF acceptance is skipped unless `DEVDIAG_LIVE_EBPF=1`.

Observed on 2026-05-25:

- Local deterministic tests passed.
- Local executable eBPF smoke returned exit code `7` with
  `trace_unavailable_reason=ebpf_capabilities_missing`, `ebpf_btf=present`,
  and all required capability evidence set to `false`.

## Live Gates

Real strace gate:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
DEVDIAG_LIVE_M7_STRACE=1 \
/usr/local/go/bin/go test ./internal/cli -run TestTraceCommand_LiveStraceJSONAcceptance -count=1 -v
```

Real eBPF gate:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
DEVDIAG_LIVE_EBPF=1 \
/usr/local/go/bin/go test ./internal/cli -run TestTraceCommand_LiveEBPFJSONAcceptance -count=1 -v
```

The eBPF gate must be run on Linux with BTF and required capabilities. In
unsupported environments, the expected release-safe result is exit code `7` with
JSON evidence explaining why eBPF could not run.
