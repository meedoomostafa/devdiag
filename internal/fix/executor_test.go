package fix

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

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

func TestConfirmTTY(t *testing.T) {
	// We can't easily test interactive confirmation without a PTY,
	// but we can test that the function signature exists.
	_ = confirmTTY
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
