package trace

import (
	"context"
	"os"
	"os/exec"
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
