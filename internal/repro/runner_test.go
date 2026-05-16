package repro

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunner_ExitCodeZero(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "echo", []string{"hello"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if !strings.Contains(res.StdoutPreview, "hello") {
		t.Errorf("expected stdout to contain 'hello', got %q", res.StdoutPreview)
	}
	if res.TimedOut {
		t.Error("expected no timeout")
	}
}

func TestRunner_ExitCodeNonZero(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "false", nil)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("expected non-zero exit code, got %d", res.ExitCode)
	}
}

func TestRunner_CommandNotFound(t *testing.T) {
	r := NewRunner()
	_, err := r.Run(context.Background(), "/nonexistent/command_xyz", nil)
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestRunner_Timeout(t *testing.T) {
	r := NewRunner()
	r.Timeout = 100 * time.Millisecond
	res, err := r.Run(context.Background(), "sleep", []string{"10"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !res.TimedOut {
		t.Error("expected timed_out=true")
	}
	if res.DurationMs > 500 {
		t.Errorf("expected duration < 500ms, got %dms", res.DurationMs)
	}
}

func TestRunner_StdoutStderrSeparate(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "bash", []string{"-c", "echo out; echo err >&2"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !strings.Contains(res.StdoutPreview, "out") {
		t.Errorf("expected stdout 'out', got %q", res.StdoutPreview)
	}
	if !strings.Contains(res.StderrPreview, "err") {
		t.Errorf("expected stderr 'err', got %q", res.StderrPreview)
	}
}

func TestRunner_WorkingDirRecorded(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "pwd", nil)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.WorkingDir == "" {
		t.Error("expected working_dir to be recorded")
	}
}

func TestRunner_EnvKeysCaptured(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "echo", []string{"hi"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(res.EnvKeys) == 0 {
		t.Error("expected env_keys to be captured")
	}
}

func TestRunner_BoundedBuffer(t *testing.T) {
	buf := newBoundedBuffer(10)
	n, _ := buf.Write([]byte("hello world"))
	if n != 11 {
		t.Errorf("expected write of 11 bytes, got %d", n)
	}
	if buf.String() != "hello worl" {
		t.Errorf("expected 'hello worl', got %q", buf.String())
	}
	if !buf.truncated {
		t.Error("expected truncated=true")
	}
}

func TestRunner_DurationRecorded(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "echo", []string{"x"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.DurationMs < 0 {
		t.Errorf("expected positive duration, got %d", res.DurationMs)
	}
}

func TestRunner_TimelineStartExit(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "echo", []string{"x"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	var hasStart, hasExit bool
	for _, ev := range res.Timeline {
		if ev.Type == "start" {
			hasStart = true
		}
		if ev.Type == "exit" {
			hasExit = true
		}
	}
	if !hasStart {
		t.Error("expected timeline start event")
	}
	if !hasExit {
		t.Error("expected timeline exit event")
	}
}
