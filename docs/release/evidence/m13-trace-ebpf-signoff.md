# M13 Trace and eBPF Live Signoff Evidence

Date: 2026-05-25T13:17:34Z

Commit: `9bcc5f693266f9be6c4336b4e04691f1840277f2`

Status: `passed`

## Environment

### go

go version go1.25.0 linux/amd64

### host

Linux fedora 7.0.8-100.fc43.x86_64 #1 SMP PREEMPT_DYNAMIC Fri May 15 15:13:18 UTC 2026 x86_64 GNU/Linux

### capabilities

CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff

### btf

present

### sysctl

kernel.perf_event_paranoid=2
kernel.unprivileged_bpf_disabled=2

### docker

Client: Docker Engine - Community
 Version:           29.5.2
 API version:       1.54
 Go version:        go1.26.3
 Git commit:        79eb04c
 Built:             Wed May 20 14:41:45 2026
 OS/Arch:           linux/amd64
 Context:           default

Server: Docker Engine - Community
 Engine:
  Version:          29.5.2
  API version:      1.54 (minimum version 1.40)
  Go version:       go1.26.3
  Git commit:       568f755
  Built:            Wed May 20 14:37:44 2026
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          v2.2.4
  GitCommit:        193637f7ee8ae5f5aa5248f49e7baa3e6164966e
 runc:
  Version:          1.3.5
  GitCommit:        v1.3.5-0-g488fc13e
 docker-init:
  Version:          0.19.0
  GitCommit:        de40ad0

## Command Results

| Command | Exit | Expected |
| --- | ---: | ---: |
| `deterministic-tests` | `0` | `0` |
| `build-devdiag` | `0` | `0` |
| `ebpf-unavailable` | `7` | `7` |
| `strace-live` | `0` | `0` |
| `ebpf-live` | `0` | `0` |

## Output Excerpts

### deterministic-tests stdout

```text
=== RUN   TestCheckEBPFSupportReportsMissingBTFAndCapabilities
--- PASS: TestCheckEBPFSupportReportsMissingBTFAndCapabilities (0.00s)
=== RUN   TestCheckEBPFSupportReportsFeatureProbeFailure
--- PASS: TestCheckEBPFSupportReportsFeatureProbeFailure (0.00s)
=== RUN   TestEBPFTracepointsAreScoped
--- PASS: TestEBPFTracepointsAreScoped (0.00s)
=== RUN   TestEBPFRecordsMapToExistingFindingsAndFilterProcessTree
--- PASS: TestEBPFRecordsMapToExistingFindingsAndFilterProcessTree (0.00s)
=== RUN   TestEBPFKernelEventsDecodeToExistingTraceFindings
--- PASS: TestEBPFKernelEventsDecodeToExistingTraceFindings (0.00s)
=== RUN   TestEBPFKernelEventsRespectRequestedScopes
--- PASS: TestEBPFKernelEventsRespectRequestedScopes (0.00s)
PASS
ok  	github.com/meedoomostafa/devdiag/internal/trace	0.005s
=== RUN   TestTraceCommand_EBPFBackendUnavailableDiagnostic
--- PASS: TestTraceCommand_EBPFBackendUnavailableDiagnostic (0.01s)
=== RUN   TestTraceCommand_EBPFBackendUnavailableJSONIncludesEvidence
--- PASS: TestTraceCommand_EBPFBackendUnavailableJSONIncludesEvidence (0.01s)
PASS
ok  	github.com/meedoomostafa/devdiag/internal/cli	0.992s
```

### deterministic-tests stderr

```text
```

### ebpf-unavailable stdout

```text
{
  "schema_version": "0.1",
  "devdiag_version": "0.1.0",
  "run_id": "2026-05-25T13:16:01Z_d4f3939c",
  "redaction_status": "default",
  "repo": {
    "root": ""
  },
  "host": {
    "os": ""
  },
  "collectors": [
    {
      "collector": "trace",
      "status": "unavailable",
      "evidence": [
        {
          "source": "trace_backend",
          "value": "ebpf"
        },
        {
          "source": "trace_command",
          "value": "true"
        },
        {
          "source": "trace_scopes",
          "value": "file,network"
        },
        {
          "source": "trace_event_count",
          "value": "0"
        },
        {
          "source": "trace_unavailable_reason",
          "value": "ebpf_capabilities_missing"
        },
        {
          "source": "ebpf_btf",
          "value": "present"
        },
        {
          "source": "ebpf_cap_eff",
          "value": "0000000000000000"
        },
        {
          "source": "ebpf_cap_bpf",
          "value": "false"
        },
        {
          "source": "ebpf_cap_perfmon",
          "value": "false"
        },
        {
          "source": "ebpf_cap_sys_admin",
          "value": "false"
        },
        {
          "source": "ebpf_tracepoint_program_type",
          "value": "unavailable"
        },
        {
          "source": "ebpf_feature_probe_error",
          "value": "detect support for TracePoint: load program: operation not permitted"
        }
      ],
      "notes": [
        "ebpf backend unavailable: ebpf_capabilities_missing"
      ]
    }
  ],
  "findings": []
}
```

### ebpf-unavailable stderr

```text
2026-05-25T13:16:01Z INF event=trace tracing command=true backend=ebpf scopes=[file network] timeout=30s
2026-05-25T13:16:01Z WRN event=trace ebpf backend unavailable: ebpf_capabilities_missing
devdiag: exit code 7
```

### strace-live stdout

```text
=== RUN   TestTraceCommand_LiveStraceJSONAcceptance
    cli_test.go:2022: strace_live_trace_backend=strace
    cli_test.go:2022: strace_live_trace_event_count=6
--- PASS: TestTraceCommand_LiveStraceJSONAcceptance (0.02s)
PASS
ok  	github.com/meedoomostafa/devdiag/internal/cli	1.789s
```

### strace-live stderr

```text
debconf: delaying package configuration, since apt-utils is not installed
go: downloading github.com/spf13/cobra v1.10.2
go: downloading gopkg.in/yaml.v3 v3.0.1
go: downloading github.com/spf13/pflag v1.0.10
go: downloading golang.org/x/term v0.43.0
go: downloading golang.org/x/sys v0.44.0
go: downloading cuelang.org/go v0.16.1
go: downloading github.com/open-policy-agent/opa v1.16.2
go: downloading github.com/cilium/ebpf v0.21.0
go: downloading github.com/cockroachdb/apd/v3 v3.2.1
go: downloading golang.org/x/text v0.36.0
go: downloading go.yaml.in/yaml/v3 v3.0.4
go: downloading github.com/emicklei/proto v1.14.3
go: downloading github.com/protocolbuffers/txtpbfmt v0.0.0-20260217160748-a481f6a22f94
go: downloading github.com/pelletier/go-toml/v2 v2.2.4
go: downloading golang.org/x/net v0.53.0
go: downloading github.com/google/uuid v1.6.0
go: downloading google.golang.org/protobuf v1.36.11
go: downloading github.com/mitchellh/go-wordwrap v1.0.1
go: downloading sigs.k8s.io/yaml v1.6.0
go: downloading github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9
go: downloading github.com/cespare/xxhash/v2 v2.3.0
go: downloading github.com/gobwas/glob v0.2.3
go: downloading github.com/lestrrat-go/jwx/v3 v3.1.0
go: downloading golang.org/x/sync v0.20.0
go: downloading github.com/tchap/go-patricia/v2 v2.3.3
go: downloading github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415
go: downloading github.com/vektah/gqlparser/v2 v2.5.32
go: downloading github.com/sirupsen/logrus v1.9.4
go: downloading github.com/yashtewari/glob-intersection v0.2.0
go: downloading github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb
go: downloading github.com/lestrrat-go/blackmagic v1.0.4
go: downloading github.com/valyala/fastjson v1.6.10
go: downloading github.com/lestrrat-go/dsig v1.2.1
go: downloading go.yaml.in/yaml/v2 v2.4.4
go: downloading github.com/lestrrat-go/option/v2 v2.0.0
go: downloading github.com/lestrrat-go/httprc/v3 v3.0.5
go: downloading golang.org/x/crypto v0.50.0
go: downloading github.com/agnivade/levenshtein v1.2.1
go: downloading github.com/lestrrat-go/httpcc v1.0.1
```

### ebpf-live stdout

```text
=== RUN   TestTraceCommand_LiveEBPFJSONAcceptance
    cli_test.go:2049: ebpf_live_trace_backend=ebpf
    cli_test.go:2049: ebpf_live_trace_event_count=5
    cli_test.go:2049: ebpf_live_ebpf_attach_mode=raw_tracepoint
    cli_test.go:2049: ebpf_live_ebpf_tracepoints_attached=raw_tracepoint/sys_enter,raw_tracepoint/sys_exit
    cli_test.go:2049: ebpf_live_ebpf_tracepoint_link_count=2
    cli_test.go:2049: ebpf_live_ebpf_raw_event_count=5
    cli_test.go:2049: ebpf_live_ebpf_event_count=5
    cli_test.go:2054: ebpf_live_findings=F-TRACE-NET-002,F-TRACE-NET-001,F-TRACE-EXEC-001,F-TRACE-FILE-001
--- PASS: TestTraceCommand_LiveEBPFJSONAcceptance (0.24s)
PASS
ok  	github.com/meedoomostafa/devdiag/internal/cli	1.516s
```

### ebpf-live stderr

```text
go: downloading github.com/spf13/cobra v1.10.2
go: downloading gopkg.in/yaml.v3 v3.0.1
go: downloading github.com/spf13/pflag v1.0.10
go: downloading golang.org/x/term v0.43.0
go: downloading golang.org/x/sys v0.44.0
go: downloading cuelang.org/go v0.16.1
go: downloading github.com/open-policy-agent/opa v1.16.2
go: downloading github.com/cilium/ebpf v0.21.0
go: downloading github.com/cockroachdb/apd/v3 v3.2.1
go: downloading golang.org/x/text v0.36.0
go: downloading go.yaml.in/yaml/v3 v3.0.4
go: downloading github.com/emicklei/proto v1.14.3
go: downloading github.com/protocolbuffers/txtpbfmt v0.0.0-20260217160748-a481f6a22f94
go: downloading github.com/pelletier/go-toml/v2 v2.2.4
go: downloading golang.org/x/net v0.53.0
go: downloading github.com/google/uuid v1.6.0
go: downloading google.golang.org/protobuf v1.36.11
go: downloading github.com/mitchellh/go-wordwrap v1.0.1
go: downloading sigs.k8s.io/yaml v1.6.0
go: downloading github.com/cespare/xxhash/v2 v2.3.0
go: downloading github.com/gobwas/glob v0.2.3
go: downloading github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415
go: downloading github.com/lestrrat-go/jwx/v3 v3.1.0
go: downloading github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9
go: downloading golang.org/x/sync v0.20.0
go: downloading github.com/yashtewari/glob-intersection v0.2.0
go: downloading github.com/tchap/go-patricia/v2 v2.3.3
go: downloading github.com/vektah/gqlparser/v2 v2.5.32
go: downloading github.com/sirupsen/logrus v1.9.4
go: downloading go.yaml.in/yaml/v2 v2.4.4
go: downloading github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb
go: downloading github.com/lestrrat-go/option/v2 v2.0.0
go: downloading github.com/lestrrat-go/dsig v1.2.1
go: downloading github.com/lestrrat-go/blackmagic v1.0.4
go: downloading github.com/valyala/fastjson v1.6.10
go: downloading github.com/lestrrat-go/httprc/v3 v3.0.5
go: downloading golang.org/x/crypto v0.50.0
go: downloading github.com/agnivade/levenshtein v1.2.1
go: downloading github.com/lestrrat-go/httpcc v1.0.1
```

