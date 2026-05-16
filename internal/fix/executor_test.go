package fix

import (
	"context"
	"os"
	"path/filepath"
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
