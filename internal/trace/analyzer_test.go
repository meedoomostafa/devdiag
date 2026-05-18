package trace

import (
	"fmt"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestAnalyzeFileNotFound(t *testing.T) {
	events := []Event{
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/missing/file"`, "O_RDONLY"}, Result: "-1", Error: "ENOENT"},
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/missing/file2"`, "O_RDONLY"}, Result: "-1", Error: "ENOENT"},
	}
	findings := Analyze(events)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "F-TRACE-FILE-001" {
		t.Fatalf("expected F-TRACE-FILE-001, got %s", f.ID)
	}
	// Should have 2 path evidence entries
	pathCount := 0
	for _, ev := range f.Evidence {
		if ev.Source == "trace_open_path" {
			pathCount++
		}
	}
	if pathCount != 2 {
		t.Fatalf("expected 2 path evidence entries, got %d", pathCount)
	}
}

func TestAnalyzeIgnoresNoisyPaths(t *testing.T) {
	events := []Event{
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/usr/share/locale/en_US"`, "O_RDONLY"}, Result: "-1", Error: "ENOENT"},
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/etc/ld.so.preload"`, "O_RDONLY"}, Result: "-1", Error: "ENOENT"},
	}
	findings := Analyze(events)
	for _, f := range findings {
		if f.ID == "F-TRACE-FILE-001" {
			t.Fatal("expected noisy ENOENT paths to be filtered")
		}
	}
}

func TestAnalyzePermissionDenied(t *testing.T) {
	events := []Event{
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/root/secret"`, "O_RDONLY"}, Result: "-1", Error: "EACCES"},
	}
	findings := Analyze(events)
	assertFinding(t, findings, "F-TRACE-FILE-002")
}

func TestAnalyzeConnectionRefused(t *testing.T) {
	events := []Event{
		{Syscall: "connect", Args: []string{"3", `{sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}`}, Result: "-1", Error: "ECONNREFUSED"},
	}
	findings := Analyze(events)
	assertFinding(t, findings, "F-TRACE-NET-001")
	f := findingByID(findings, "F-TRACE-NET-001")
	hasHost := false
	hasPort := false
	for _, ev := range f.Evidence {
		if ev.Source == "trace_connect_host" {
			hasHost = true
		}
		if ev.Source == "trace_connect_port" {
			hasPort = true
		}
	}
	if !hasHost || !hasPort {
		t.Fatal("expected host and port evidence")
	}
}

func TestAnalyzeUnixSocketConnectionRefused(t *testing.T) {
	events := []Event{
		{Syscall: "connect", Args: []string{"3", `{sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}`}, Result: "-1", Error: "ECONNREFUSED"},
	}
	findings := Analyze(events)
	f := findingByID(findings, "F-TRACE-NET-001")
	assertContainsFixHint(t, f, "verify-unix-socket")
}

func TestAnalyzeExecveENOENT(t *testing.T) {
	events := []Event{
		{Syscall: "execve", Args: []string{`"/wrong/node"`, `["node"]`, "0x7fff"}, Result: "-1", Error: "ENOENT"},
	}
	findings := Analyze(events)
	assertFinding(t, findings, "F-TRACE-EXEC-001")
	f := findingByID(findings, "F-TRACE-EXEC-001")
	assertEvidence(t, f, "trace_exec_path", "/wrong/node")
}

func TestAnalyzeBindAddressInUse(t *testing.T) {
	events := []Event{
		{Syscall: "bind", Args: []string{"3", `{sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}`}, Result: "-1", Error: "EADDRINUSE"},
	}
	findings := Analyze(events)
	assertFinding(t, findings, "F-TRACE-NET-002")
	f := findingByID(findings, "F-TRACE-NET-002")
	assertEvidence(t, f, "trace_bind_port", "5432")
}

func TestAnalyzeDNSResolverFileFailure(t *testing.T) {
	events := []Event{
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/etc/resolv.conf"`, "O_RDONLY"}, Result: "-1", Error: "ENOENT"},
	}
	findings := Analyze(events)
	assertFinding(t, findings, "F-TRACE-DNS-001")
	if f := findingByID(findings, "F-TRACE-FILE-001"); f.ID != "" {
		t.Fatal("expected resolver failure to prefer F-TRACE-DNS-001 over F-TRACE-FILE-001")
	}
}

func TestAnalyzeDNSPort53Failure(t *testing.T) {
	events := []Event{
		{Syscall: "sendto", Args: []string{"3", `"query"`, "5", "0", `{sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}`, "16"}, Result: "-1", Error: "ETIMEDOUT"},
	}
	findings := Analyze(events)
	assertFinding(t, findings, "F-TRACE-DNS-001")
	if f := findingByID(findings, "F-TRACE-NET-001"); f.ID != "" {
		t.Fatal("expected DNS port 53 failure to avoid generic connection-refused finding")
	}
}

func TestAnalyzeEvidenceCap(t *testing.T) {
	var events []Event
	for i := 0; i < maxEvidencePerFinding+5; i++ {
		events = append(events, Event{
			Syscall: "openat",
			Args:    []string{"AT_FDCWD", fmt.Sprintf(`"/missing/%d"`, i), "O_RDONLY"},
			Result:  "-1",
			Error:   "ENOENT",
		})
	}
	findings := Analyze(events)
	f := findingByID(findings, "F-TRACE-FILE-001")
	if len(f.Evidence) > maxEvidencePerFinding+1 {
		t.Fatalf("expected at most %d+1 evidence entries, got %d", maxEvidencePerFinding, len(f.Evidence))
	}
	hasOmitted := false
	for _, ev := range f.Evidence {
		if ev.Source == "trace_evidence_omitted" {
			hasOmitted = true
			break
		}
	}
	if !hasOmitted {
		t.Fatal("expected trace_evidence_omitted summary when capped")
	}
}

func TestAnalyzeDeduplicatesRepeatedErrors(t *testing.T) {
	events := []Event{
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/secret"`, "O_RDONLY"}, Result: "-1", Error: "EACCES"},
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/secret"`, "O_RDONLY"}, Result: "-1", Error: "EACCES"},
		{Syscall: "openat", Args: []string{"AT_FDCWD", `"/secret"`, "O_RDONLY"}, Result: "-1", Error: "EACCES"},
	}
	findings := Analyze(events)
	f := findingByID(findings, "F-TRACE-FILE-002")
	if f.ID == "" {
		t.Fatal("expected F-TRACE-FILE-002")
	}
	pathCount := 0
	for _, ev := range f.Evidence {
		if ev.Source == "trace_open_path" {
			pathCount++
		}
	}
	if pathCount != 1 {
		t.Fatalf("expected 1 deduplicated path evidence, got %d", pathCount)
	}
}

func assertFinding(t *testing.T, findings []schema.Finding, id string) {
	for _, f := range findings {
		if f.ID == id {
			return
		}
	}
	t.Fatalf("missing finding %s", id)
}

func findingByID(findings []schema.Finding, id string) schema.Finding {
	for _, f := range findings {
		if f.ID == id {
			return f
		}
	}
	return schema.Finding{}
}

func assertContainsFixHint(t *testing.T, f schema.Finding, hint string) {
	for _, h := range f.FixHints {
		if h == hint {
			return
		}
	}
	t.Fatalf("missing fix hint %q in finding %s", hint, f.ID)
}

func assertEvidence(t *testing.T, f schema.Finding, source, value string) {
	t.Helper()
	for _, ev := range f.Evidence {
		if ev.Source == source && ev.Value == value {
			return
		}
	}
	t.Fatalf("missing evidence %s=%s in finding %s: %#v", source, value, f.ID, f.Evidence)
}
