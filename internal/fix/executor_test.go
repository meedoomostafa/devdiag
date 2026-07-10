package fix

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestExecutorRoutesThroughInjectedRunner(t *testing.T) {
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"chmod +x /tmp/script.sh": {ExitCode: 0, Stdout: "ok"},
	})
	executor := NewExecutor(nil)
	executor.Runner = fake

	proposal := schema.FixProposal{
		FindingID: "F-TEST-001",
		HintID:    "chmod-script",
		Class:     schema.FixSafe,
		Bin:       "chmod",
		Args:      []string{"+x", "/tmp/script.sh"},
	}
	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if exec == nil || !exec.Success {
		t.Fatalf("expected success, got %#v", exec)
	}
	if exec.Stdout != "ok" {
		t.Errorf("stdout = %q, want %q from fake runner", exec.Stdout, "ok")
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("fake runner calls = %d, want 1", len(fake.Calls))
	}
	if fake.Calls[0].Command != "chmod" {
		t.Errorf("command = %q, want chmod", fake.Calls[0].Command)
	}
}

func TestExecutorPermissionDeniedReportedAsFailure(t *testing.T) {
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"privcmd": {ExitCode: -1, PermissionDenied: true},
	})
	executor := NewExecutor(nil)
	executor.Runner = fake

	proposal := schema.FixProposal{
		FindingID: "F-TEST-003",
		HintID:    "priv",
		Class:     schema.FixSafe,
		Bin:       "privcmd",
	}
	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err == nil {
		t.Fatal("expected error for permission-denied fix")
	}
	if exec == nil || exec.Success {
		t.Fatalf("expected failed execution, got %#v", exec)
	}
	if !strings.Contains(exec.Error, "permission denied") {
		t.Errorf("error = %q, want permission-denied mention", exec.Error)
	}
}

func TestExecutorTimeoutReportedAsFailure(t *testing.T) {
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"slowcmd": {ExitCode: -1, TimedOut: true},
	})
	executor := NewExecutor(nil)
	executor.Runner = fake

	proposal := schema.FixProposal{
		FindingID: "F-TEST-002",
		HintID:    "slow",
		Class:     schema.FixSafe,
		Bin:       "slowcmd",
	}
	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err == nil {
		t.Fatal("expected error for timed-out fix")
	}
	if exec == nil || exec.Success {
		t.Fatalf("expected failed execution, got %#v", exec)
	}
	if !strings.Contains(exec.Error, "timed out") {
		t.Errorf("error = %q, want timeout mention", exec.Error)
	}
}

func TestExecutorBlocked(t *testing.T) {
	executor := NewExecutor(nil)
	proposal := schema.FixProposal{
		FindingID:     "F-TEST-001",
		HintID:        "blocked",
		Class:         schema.FixBlocked,
		BlockedReason: "test block",
	}
	_, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err == nil {
		t.Fatal("expected error for blocked fix")
	}
}

func TestExecutorDryRun(t *testing.T) {
	executor := NewExecutor(nil)
	proposal := schema.FixProposal{
		FindingID: "F-TEST-001",
		HintID:    "chmod-script",
		Class:     schema.FixSafe,
		Bin:       "chmod",
		Args:      []string{"+x", "test.sh"},
	}
	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: false})
	if err != nil {
		t.Fatalf("dry-run error: %v", err)
	}
	if exec != nil {
		t.Fatal("expected nil execution on dry-run")
	}
}

func TestExecutorManual(t *testing.T) {
	executor := NewExecutor(nil)
	proposal := schema.FixProposal{
		FindingID: "F-TEST-001",
		HintID:    "change-compose-port",
		Class:     schema.FixManual,
	}
	_, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err == nil {
		t.Fatal("expected error for manual fix")
	}
}

func TestExecutorGuardedNoFresh(t *testing.T) {
	executor := NewExecutor(nil)
	proposal := schema.FixProposal{
		FindingID:      "F-TEST-001",
		HintID:         "stop-service",
		Class:          schema.FixGuarded,
		Source:         schema.FixSourceSavedReport,
		ConfirmMessage: "test",
	}
	_, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true, Fresh: false})
	if err == nil {
		t.Fatal("expected error for guarded fix without --fresh")
	}
}

func TestExecutorSafe(t *testing.T) {
	// Create a real temp file to chmod
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "script.sh")
	if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\necho hello\n"), 0644); err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	// Audit log in temp dir
	auditPath := filepath.Join(tmpDir, "audit.ndjson")
	executor := NewExecutor(NewAuditLog(auditPath))

	proposal := schema.FixProposal{
		FindingID: "F-FS-001",
		HintID:    "chmod-script",
		Class:     schema.FixSafe,
		Bin:       "chmod",
		Args:      []string{"+x", tmpFile},
		Rollback:  []string{"chmod", "-x", tmpFile},
	}

	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err != nil {
		t.Fatalf("safe fix failed: %v", err)
	}
	if exec == nil {
		t.Fatal("expected execution result")
	}
	if !exec.Success {
		t.Fatalf("expected success, got exit code %d: %s", exec.ExitCode, exec.Stderr)
	}

	// Verify file is executable
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	if info.Mode().Perm()&0111 == 0 {
		t.Fatal("expected file to be executable")
	}

	// Verify audit log was written
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected audit log entry")
	}
}

func TestExecutorGuardedInteractiveConfirmationExecutes(t *testing.T) {
	tmpDir := t.TempDir()
	markerPath := filepath.Join(tmpDir, "daemon-reload-called")
	fakeSystemctl := filepath.Join(tmpDir, "systemctl")
	if err := os.WriteFile(fakeSystemctl, []byte("#!/bin/sh\ntouch "+markerPath+"\n"), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	if _, err := io.WriteString(stdinW, "yes\n"); err != nil {
		t.Fatalf("write confirmation: %v", err)
	}
	if err := stdinW.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = stdinR
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = stdinR.Close()
	})

	auditPath := filepath.Join(tmpDir, "audit.ndjson")
	executor := NewExecutor(NewAuditLog(auditPath))
	proposal := schema.FixProposal{
		FindingID:      "F-SVC-001",
		HintID:         "systemctl-daemon-reload",
		Class:          schema.FixGuarded,
		Source:         schema.FixSourceFreshScan,
		Bin:            fakeSystemctl,
		Args:           []string{"daemon-reload"},
		ConfirmMessage: "Reload systemd manager configuration on this host.",
	}
	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true, Fresh: true, Interactive: true})
	if err != nil {
		t.Fatalf("guarded fix failed: %v", err)
	}
	if exec == nil || !exec.Success {
		t.Fatalf("expected successful guarded execution, got %#v", exec)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("expected fake systemctl marker: %v", err)
	}
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), `"hint_id":"systemctl-daemon-reload"`) || !strings.Contains(string(auditData), `"success":true`) {
		t.Fatalf("audit log missing guarded execution: %s", string(auditData))
	}
}

func TestExecutorSafeFailure(t *testing.T) {
	executor := NewExecutor(nil)
	proposal := schema.FixProposal{
		FindingID: "F-TEST-001",
		HintID:    "bad-cmd",
		Class:     schema.FixSafe,
		Bin:       "false",
		Args:      []string{},
	}
	exec, err := executor.Execute(context.Background(), proposal, ExecutorOptions{Apply: true})
	if err == nil {
		t.Fatal("expected error for failing command")
	}
	if exec == nil {
		t.Fatal("expected execution result")
	}
	if exec.Success {
		t.Fatal("expected failure")
	}
	if exec.ExitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exec.ExitCode)
	}
}

func TestExecutorGuardedConfirmViaInjectedIO(t *testing.T) {
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"systemctl daemon-reload": {ExitCode: 0},
	})
	tests := []struct {
		name    string
		input   string
		wantRun bool
	}{
		{"accepts y", "y\n", true},
		{"accepts yes", "yes\n", true},
		{"declines n", "n\n", false},
		{"declines empty", "\n", false},
		{"declines eof", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake.Calls = nil
			executor := NewExecutor(nil)
			executor.Runner = fake

			var prompt strings.Builder
			proposal := schema.FixProposal{
				FindingID:      "F-SVC-001",
				HintID:         "systemctl-daemon-reload",
				Class:          schema.FixGuarded,
				Source:         schema.FixSourceFreshScan,
				Bin:            "systemctl",
				Args:           []string{"daemon-reload"},
				ConfirmMessage: "risky",
			}
			_, err := executor.Execute(context.Background(), proposal, ExecutorOptions{
				Apply:       true,
				Fresh:       true,
				Interactive: true,
				ConfirmIn:   strings.NewReader(tt.input),
				ConfirmOut:  &prompt,
			})
			ran := len(fake.Calls) > 0
			if ran != tt.wantRun {
				t.Errorf("command ran = %v, want %v (err=%v)", ran, tt.wantRun, err)
			}
			if tt.wantRun && err != nil {
				t.Errorf("unexpected error on confirm: %v", err)
			}
			if !tt.wantRun && err == nil {
				t.Error("expected decline error")
			}
			if !strings.Contains(prompt.String(), "Apply? [y/N]") {
				t.Errorf("prompt missing confirmation question: %q", prompt.String())
			}
		})
	}
}

func TestAuditLog_RedactsRefuseReason(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.ndjson")
	executor := NewExecutor(NewAuditLog(auditPath))

	proposal := schema.FixProposal{
		FindingID:     "F1",
		Class:         schema.FixBlocked,
		BlockedReason: "API_KEY=secret123",
	}

	_, _ = executor.Execute(context.Background(), proposal, ExecutorOptions{
		Apply:  true,
		Redact: func(s string) string { return strings.ReplaceAll(s, "secret123", "<redacted>") },
	})

	data, _ := os.ReadFile(auditPath)
	if strings.Contains(string(data), "secret123") {
		t.Errorf("audit log leaked secret in RefuseReason: %s", data)
	}
	if !strings.Contains(string(data), "redacted") {
		t.Errorf("audit log missing redaction in RefuseReason: %s", data)
	}
}
