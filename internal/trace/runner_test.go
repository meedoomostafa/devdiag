package trace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRunnerWithStrace(t *testing.T) {
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not installed")
	}
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true unavailable")
	}
	r := &Runner{Timeout: 5 * time.Second}
	res, err := r.Run(context.Background(), []Scope{ScopeFile}, "/bin/true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Command != "/bin/true" {
		t.Fatalf("expected command /bin/true, got %s", res.Command)
	}
	if len(res.Args) != 0 {
		t.Fatalf("expected no args, got %v", res.Args)
	}
	if res.TraceUnavailable {
		// Some CI environments block ptrace; skip but log
		t.Skip("ptrace unavailable in this environment")
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
}

func TestRunnerEmptyCommand(t *testing.T) {
	r := &Runner{Timeout: 5 * time.Second}
	_, err := r.Run(context.Background(), []Scope{ScopeFile}, "")
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestRunnerTimeout(t *testing.T) {
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not installed")
	}
	r := &Runner{Timeout: 500 * time.Millisecond}
	res, err := r.Run(context.Background(), []Scope{ScopeFile}, "sleep", "10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("expected timed out")
	}
	if res.ExitCode == 0 {
		t.Fatal("expected non-zero exit code after timeout")
	}
}

func TestBuildStraceFilters(t *testing.T) {
	filters := buildStraceFilters([]Scope{ScopeFile, ScopeNetwork})
	want := []string{"-e", "trace=%file,%network"}
	if len(filters) != len(want) || filters[0] != want[0] || filters[1] != want[1] {
		t.Fatalf("unexpected filters: %v", filters)
	}
}

func TestBuildStraceArgsUsesSingleFileFollowForksAndSeccomp(t *testing.T) {
	args := buildStraceArgs([]Scope{ScopeFile, ScopeProcess, ScopeNetwork}, "/tmp/trace.log", "true", nil)
	if !slices.Contains(args, "-f") {
		t.Fatalf("expected -f in args: %v", args)
	}
	if slices.Contains(args, "-ff") {
		t.Fatalf("did not expect -ff in args: %v", args)
	}
	if !slices.Contains(args, "--seccomp-bpf") {
		t.Fatalf("expected --seccomp-bpf in args: %v", args)
	}
	if !containsAdjacent(args, "-o", "/tmp/trace.log") {
		t.Fatalf("expected -o /tmp/trace.log in args: %v", args)
	}
	if !containsAdjacent(args, "-e", "trace=%file,%process,%network") {
		t.Fatalf("expected scoped trace filter in args: %v", args)
	}
}

func TestDetectSeccompDegraded(t *testing.T) {
	stderr := "strace: seccomp-bpf requested but not enabled\n"
	if !isSeccompBPFDegraded(stderr) {
		t.Fatalf("expected seccomp degradation to be detected")
	}
	if isTraceUnavailable(stderr) {
		t.Fatalf("seccomp degradation should not be treated as trace unavailable")
	}
}

func TestSeccompDegradedNoteMentionsHeavyCommandSlowdown(t *testing.T) {
	res := &Result{}
	markSeccompBPFDegraded(res)
	if !res.SeccompDegraded {
		t.Fatal("expected SeccompDegraded to be true")
	}
	if len(res.Notes) == 0 {
		t.Fatal("expected degradation note")
	}
	note := strings.Join(res.Notes, "\n")
	if !strings.Contains(note, "dramatically slower") {
		t.Fatalf("expected heavy-command slowdown note, got %q", note)
	}
}

func TestRunnerDoesNotMarkSeccompAppliedWhenTraceUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake strace shell script is not portable to windows")
	}
	dir := t.TempDir()
	stracePath := filepath.Join(dir, "strace")
	script := "#!/bin/sh\necho 'strace: PTRACE_TRACEME: Operation not permitted' >&2\nexit 1\n"
	if err := os.WriteFile(stracePath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake strace: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, err := (&Runner{Timeout: 5 * time.Second}).Run(context.Background(), []Scope{ScopeFile}, "/bin/true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TraceUnavailable {
		t.Fatalf("expected trace unavailable, got %#v", res)
	}
	if res.SeccompApplied {
		t.Fatalf("expected seccomp not applied for unavailable trace, got %#v", res)
	}
}

func TestRunEBPFDiagnosticStubUnavailable(t *testing.T) {
	res, err := RunEBPF(context.Background(), []Scope{ScopeFile}, "true")
	if err != nil {
		t.Fatalf("RunEBPF returned error: %v", err)
	}
	if res.Backend != "ebpf" {
		t.Fatalf("expected ebpf backend, got %q", res.Backend)
	}
	if !res.TraceUnavailable {
		t.Fatal("expected eBPF diagnostic stub to be unavailable")
	}
	if res.UnavailableReason == "" {
		t.Fatal("expected stable unavailable reason")
	}
}

func TestIsTraceUnavailable(t *testing.T) {
	cases := []struct {
		stderr string
		want   bool
	}{
		{"strace: PTRACE_TRACEME: Operation not permitted", true},
		{"ptrace: Permission denied", true},
		{"strace: attach: could not attach", true},
		{"some normal error", false},
	}
	for _, c := range cases {
		got := isTraceUnavailable(c.stderr)
		if got != c.want {
			t.Fatalf("isTraceUnavailable(%q) = %v, want %v", c.stderr, got, c.want)
		}
	}
}

func containsAdjacent(values []string, first, second string) bool {
	for i := 0; i+1 < len(values); i++ {
		if values[i] == first && values[i+1] == second {
			return true
		}
	}
	return false
}
