package trace

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBTFPath        = "/sys/kernel/btf/vmlinux"
	defaultProcStatusPath = "/proc/self/status"

	capSysAdmin = 21
	capPerfmon  = 38
	capBPF      = 39
)

type ebpfEnvironment struct {
	BTFPath        string
	ProcStatusPath string
	FeatureProbe   func() error
}

type ebpfSupportReport struct {
	Supported bool
	Reason    string
	Evidence  []TraceEvidence
}

type ebpfFeatureUnavailableError string

func (e ebpfFeatureUnavailableError) Error() string {
	return string(e)
}

func errEBPFFeatureUnavailable(message string) error {
	return ebpfFeatureUnavailableError(message)
}

// EBPFRecord is the decoded userspace representation consumed by the analyzer.
// Kernel collectors and tests should populate records only for traced process
// tree members.
type EBPFRecord struct {
	Timestamp time.Time
	PID       int
	Scope     Scope
	Syscall   string
	Args      []string
	Result    string
	Error     string
	Duration  time.Duration
}

func EventsFromEBPFRecords(records []EBPFRecord, processTree map[int]bool, scopes []Scope) []Event {
	scopeSet := make(map[Scope]bool, len(scopes))
	for _, scope := range scopes {
		scopeSet[scope] = true
	}
	events := make([]Event, 0, len(records))
	for _, record := range records {
		if len(processTree) > 0 && !processTree[record.PID] {
			continue
		}
		if len(scopeSet) > 0 && !scopeSet[record.Scope] {
			continue
		}
		events = append(events, Event{
			Timestamp: record.Timestamp,
			PID:       record.PID,
			Syscall:   record.Syscall,
			Args:      append([]string(nil), record.Args...),
			Result:    record.Result,
			Error:     record.Error,
			Duration:  record.Duration,
		})
	}
	return events
}

func ebpfTracepointsForScopes(scopes []Scope) []string {
	seen := make(map[string]bool)
	var tracepoints []string
	add := func(group, name string) {
		value := group + "/" + name
		if !seen[value] {
			seen[value] = true
			tracepoints = append(tracepoints, value)
		}
	}
	if len(scopes) > 0 {
		add("sched", "sched_process_fork")
	}
	for _, scope := range scopes {
		switch scope {
		case ScopeFile:
			add("syscalls", "sys_enter_openat")
			add("syscalls", "sys_exit_openat")
		case ScopeProcess:
			add("syscalls", "sys_enter_execve")
			add("syscalls", "sys_exit_execve")
			add("syscalls", "sys_enter_clone")
			add("syscalls", "sys_enter_fork")
			add("syscalls", "sys_enter_vfork")
		case ScopeNetwork:
			add("syscalls", "sys_enter_connect")
			add("syscalls", "sys_exit_connect")
			add("syscalls", "sys_enter_bind")
			add("syscalls", "sys_exit_bind")
		}
	}
	return tracepoints
}

func defaultEBPFEnvironment(featureProbe func() error) ebpfEnvironment {
	return ebpfEnvironment{
		BTFPath:        defaultBTFPath,
		ProcStatusPath: defaultProcStatusPath,
		FeatureProbe:   featureProbe,
	}
}

func checkEBPFSupport(env ebpfEnvironment) ebpfSupportReport {
	if env.BTFPath == "" {
		env.BTFPath = defaultBTFPath
	}
	if env.ProcStatusPath == "" {
		env.ProcStatusPath = defaultProcStatusPath
	}

	report := ebpfSupportReport{}
	if _, err := os.Stat(env.BTFPath); err != nil {
		report.Evidence = append(report.Evidence, TraceEvidence{Source: "ebpf_btf", Value: "missing"})
		if report.Reason == "" {
			report.Reason = "ebpf_btf_missing"
		}
	} else {
		report.Evidence = append(report.Evidence, TraceEvidence{Source: "ebpf_btf", Value: "present"})
	}

	capEff, err := readCapEff(env.ProcStatusPath)
	if err != nil {
		report.Evidence = append(report.Evidence, TraceEvidence{Source: "ebpf_proc_status", Value: "unreadable"})
		if report.Reason == "" {
			report.Reason = "ebpf_capabilities_unknown"
		}
	} else {
		report.Evidence = append(report.Evidence, TraceEvidence{Source: "ebpf_cap_eff", Value: formatCapHex(capEff)})
		hasBPF := hasCapability(capEff, capBPF)
		hasPerfmon := hasCapability(capEff, capPerfmon)
		hasSysAdmin := hasCapability(capEff, capSysAdmin)
		report.Evidence = append(report.Evidence,
			TraceEvidence{Source: "ebpf_cap_bpf", Value: fmt.Sprintf("%t", hasBPF)},
			TraceEvidence{Source: "ebpf_cap_perfmon", Value: fmt.Sprintf("%t", hasPerfmon)},
			TraceEvidence{Source: "ebpf_cap_sys_admin", Value: fmt.Sprintf("%t", hasSysAdmin)},
		)
		if !((hasBPF && hasPerfmon) || hasSysAdmin) && report.Reason == "" {
			report.Reason = "ebpf_capabilities_missing"
		}
	}

	if env.FeatureProbe != nil {
		if err := env.FeatureProbe(); err != nil {
			report.Evidence = append(report.Evidence,
				TraceEvidence{Source: "ebpf_tracepoint_program_type", Value: "unavailable"},
				TraceEvidence{Source: "ebpf_feature_probe_error", Value: err.Error()},
			)
			if report.Reason == "" {
				report.Reason = "ebpf_tracepoint_unavailable"
			}
		} else {
			report.Evidence = append(report.Evidence, TraceEvidence{Source: "ebpf_tracepoint_program_type", Value: "available"})
		}
	}

	report.Supported = report.Reason == ""
	return report
}

func readCapEff(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			return strconv.ParseUint(value, 16, 64)
		}
	}
	return 0, fmt.Errorf("CapEff not found")
}

func hasCapability(capEff uint64, capability uint) bool {
	return capEff&(uint64(1)<<capability) != 0
}

func formatCapHex(capEff uint64) string {
	return fmt.Sprintf("%016x", capEff)
}
