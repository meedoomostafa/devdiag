package trace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCheckEBPFSupportReportsMissingBTFAndCapabilities(t *testing.T) {
	statusPath := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(statusPath, []byte("Name:\ttest\nCapEff:\t0000000000000000\n"), 0o644); err != nil {
		t.Fatalf("write proc status fixture: %v", err)
	}
	report := checkEBPFSupport(ebpfEnvironment{
		BTFPath:        filepath.Join(t.TempDir(), "missing-vmlinux"),
		ProcStatusPath: statusPath,
		FeatureProbe:   func() error { return nil },
	})

	if report.Supported {
		t.Fatalf("supported = true, want false; report=%+v", report)
	}
	if report.Reason != "ebpf_btf_missing" {
		t.Fatalf("reason = %q, want ebpf_btf_missing; report=%+v", report.Reason, report)
	}
	assertTraceEvidence(t, report.Evidence, "ebpf_btf", "missing")
	assertTraceEvidence(t, report.Evidence, "ebpf_cap_bpf", "false")
	assertTraceEvidence(t, report.Evidence, "ebpf_cap_perfmon", "false")
}

func TestCheckEBPFSupportReportsFeatureProbeFailure(t *testing.T) {
	dir := t.TempDir()
	btfPath := filepath.Join(dir, "vmlinux")
	statusPath := filepath.Join(dir, "status")
	if err := os.WriteFile(btfPath, []byte("btf"), 0o644); err != nil {
		t.Fatalf("write btf fixture: %v", err)
	}
	capEff := uint64(1<<capBPF | 1<<capPerfmon)
	if err := os.WriteFile(statusPath, []byte("CapEff:\t"+formatCapHex(capEff)+"\n"), 0o644); err != nil {
		t.Fatalf("write proc status fixture: %v", err)
	}

	report := checkEBPFSupport(ebpfEnvironment{
		BTFPath:        btfPath,
		ProcStatusPath: statusPath,
		FeatureProbe:   func() error { return errEBPFFeatureUnavailable("tracepoint unavailable") },
	})

	if report.Supported {
		t.Fatalf("supported = true, want false; report=%+v", report)
	}
	if report.Reason != "ebpf_tracepoint_unavailable" {
		t.Fatalf("reason = %q, want ebpf_tracepoint_unavailable; report=%+v", report.Reason, report)
	}
	assertTraceEvidence(t, report.Evidence, "ebpf_tracepoint_program_type", "unavailable")
}

func TestEBPFTracepointsAreScoped(t *testing.T) {
	got := ebpfTracepointsForScopes([]Scope{ScopeFile, ScopeProcess, ScopeNetwork})
	for _, want := range []string{
		"syscalls/sys_enter_openat",
		"syscalls/sys_enter_execve",
		"syscalls/sys_enter_connect",
		"syscalls/sys_enter_bind",
	} {
		if !containsString(got, want) {
			t.Fatalf("tracepoints missing %q: %v", want, got)
		}
	}
	if containsString(ebpfTracepointsForScopes([]Scope{ScopeNetwork}), "syscalls/sys_enter_openat") {
		t.Fatalf("network scope should not include file tracepoints")
	}
}

func TestEBPFRecordsMapToExistingFindingsAndFilterProcessTree(t *testing.T) {
	records := []EBPFRecord{
		{PID: 100, Scope: ScopeNetwork, Syscall: "connect", Args: []string{`{sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}`}, Result: "-1", Error: "ECONNREFUSED"},
		{PID: 200, Scope: ScopeNetwork, Syscall: "connect", Args: []string{`{sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("127.0.0.1")}`}, Result: "-1", Error: "ECONNREFUSED"},
		{PID: 100, Scope: ScopeFile, Syscall: "openat", Args: []string{`"/tmp/missing"`}, Result: "-1", Error: "ENOENT"},
	}
	events := EventsFromEBPFRecords(records, map[int]bool{100: true}, []Scope{ScopeNetwork})
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one filtered network event", events)
	}
	findings := Analyze(events)
	if len(findings) != 1 || findings[0].ID != "F-TRACE-NET-001" {
		t.Fatalf("findings = %+v, want F-TRACE-NET-001", findings)
	}
	assertEvidenceValue(t, findings[0].Evidence, "trace_connect_port", "5432")
	assertEvidenceValueAbsent(t, findings[0].Evidence, "trace_connect_port", "9999")
}

func assertTraceEvidence(t *testing.T, evidence []TraceEvidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			return
		}
	}
	t.Fatalf("missing trace evidence %s=%s in %+v", source, value, evidence)
}

func assertEvidenceValue(t *testing.T, evidence []schema.Evidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			return
		}
	}
	t.Fatalf("missing evidence %s=%s in %+v", source, value, evidence)
}

func assertEvidenceValueAbsent(t *testing.T, evidence []schema.Evidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			t.Fatalf("unexpected evidence %s=%s in %+v", source, value, evidence)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
