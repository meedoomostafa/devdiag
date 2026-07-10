package repro

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/redact"
)

func TestRunner_RoutesThroughInjectedRunner(t *testing.T) {
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"mycmd --flag": {ExitCode: 0, Stdout: "fake-out", Stderr: "fake-err"},
	})
	r := NewRunner()
	r.CmdRunner = fake

	res, err := r.Run(context.Background(), "mycmd", []string{"--flag"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(res.StdoutPreview, "fake-out") {
		t.Errorf("stdout preview = %q, want fake runner output", res.StdoutPreview)
	}
	if !strings.Contains(res.StderrPreview, "fake-err") {
		t.Errorf("stderr preview = %q, want fake runner stderr", res.StderrPreview)
	}
	if len(fake.Calls) != 1 || fake.Calls[0].Command != "mycmd" {
		t.Fatalf("fake calls = %#v, want single mycmd call", fake.Calls)
	}
}

func TestRunner_TruncationReportedFromRunner(t *testing.T) {
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"bigcmd": {ExitCode: 0, Stdout: "partial", StdoutTruncated: true, StdoutSeenBytes: 999, StderrSeenBytes: 0},
	})
	r := NewRunner()
	r.CmdRunner = fake

	res, err := r.Run(context.Background(), "bigcmd", nil)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !res.Truncated {
		t.Error("expected truncated=true")
	}
	if res.OriginalBytes != 999 {
		t.Errorf("original bytes = %d, want 999", res.OriginalBytes)
	}
}

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

func TestRunner_BoundedCapture(t *testing.T) {
	r := NewRunner()
	r.StdoutCap = 10
	res, err := r.Run(context.Background(), "echo", []string{"hello world, this is long"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !res.Truncated {
		t.Error("expected truncated=true for output over cap")
	}
	if res.OriginalBytes <= res.StoredBytes-int64(len(cmdrunner.TruncationMarker)) {
		t.Errorf("original bytes %d should exceed stored payload", res.OriginalBytes)
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

func TestRunner_SensitiveEnvKeyExcludesPath(t *testing.T) {
	if isSensitiveEnvKey("PATH") {
		t.Error("PATH should not be flagged as sensitive")
	}
	if isSensitiveEnvKey("HOME") {
		t.Error("HOME should not be flagged as sensitive")
	}
	if !isSensitiveEnvKey("API_KEY") {
		t.Error("API_KEY should be flagged as sensitive")
	}
	if !isSensitiveEnvKey("DATABASE_URL") {
		t.Error("DATABASE_URL should be flagged as sensitive")
	}
}

func TestRunner_RedactsURLCredentials(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "echo", []string{"postgres://admin:secret123@localhost:5432/db"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if strings.Contains(res.StdoutPreview, "secret123") {
		t.Errorf("password should be redacted, got: %s", res.StdoutPreview)
	}
	if !strings.Contains(res.StdoutPreview, "<redacted>") {
		t.Errorf("expected <redacted> in output, got: %s", res.StdoutPreview)
	}
}

func TestRunner_RedactsJWT(t *testing.T) {
	r := NewRunner()
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	res, err := r.Run(context.Background(), "echo", []string{jwt})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if strings.Contains(res.StdoutPreview, jwt) {
		t.Errorf("JWT should be redacted, got: %s", res.StdoutPreview)
	}
}

func TestRunner_RedactsCLISecrets(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "echo", []string{"--api-key=secretvalue"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if strings.Contains(res.StdoutPreview, "secretvalue") {
		t.Errorf("--api-key value should be redacted, got: %s", res.StdoutPreview)
	}
	if !strings.Contains(res.StdoutPreview, "<redacted>") {
		t.Errorf("expected <redacted> in output, got: %s", res.StdoutPreview)
	}
}

func TestRunner_RedactsEnvValues(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), "printf", []string{"API_KEY=secret123"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if strings.Contains(res.StdoutPreview, "secret123") {
		t.Errorf("env value should be redacted, got: %s", res.StdoutPreview)
	}
}

func TestRunner_EngineOverride(t *testing.T) {
	r := NewRunner()
	r.Redactor = redact.NewEngine(redact.LevelOff)
	res, err := r.Run(context.Background(), "echo", []string{"--api-key=secretvalue"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !strings.Contains(res.StdoutPreview, "secretvalue") {
		t.Errorf("LevelOff should not redact, got: %s", res.StdoutPreview)
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
