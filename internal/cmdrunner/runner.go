package cmdrunner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// Result captures the outcome of an executed command.
type Result struct {
	Command          string
	Args             []string
	Stdout           string
	Stderr           string
	ExitCode         int
	Duration         time.Duration
	TimedOut         bool
	NotFound         bool
	PermissionDenied bool
}

// CommandRunner abstracts external command execution for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) Result
}

// maxCaptureBytes limits stdout/stderr capture to prevent OOM from runaway processes.
const maxCaptureBytes = 10 * 1024 * 1024 // 10 MB

// RealRunner is the production implementation using exec.CommandContext.
type RealRunner struct{}

// NewRealRunner creates a production command runner.
func NewRealRunner() *RealRunner {
	return &RealRunner{}
}

// Run executes the named command with the given arguments.
// It never uses sh -c. Stdout and stderr are captured separately.
func (r *RealRunner) Run(ctx context.Context, name string, args ...string) Result {
	start := time.Now()
	res := Result{
		Command: name,
		Args:    append([]string(nil), args...),
	}

	cmd := exec.CommandContext(ctx, name, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = limitCapture(stdoutBuf.String())
	res.Stderr = limitCapture(stderrBuf.String())

	if err == nil {
		res.ExitCode = 0
		return res
	}

	// Classify the error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
		res.TimedOut = true
	}

	if pathErr, ok := err.(*exec.Error); ok && pathErr.Err == exec.ErrNotFound {
		res.NotFound = true
		res.ExitCode = -1
		return res
	}

	// Check for permission denied via syscall error
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
		if len(exitErr.Stderr) > 0 {
			res.Stderr = string(exitErr.Stderr)
		}
		// Heuristic: permission denied from stderr
		if isPermissionDenied(res.Stderr) {
			res.PermissionDenied = true
		}
	} else {
		res.ExitCode = -1
		// Check if the underlying error is permission denied
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			res.PermissionDenied = true
		}
	}

	return res
}

func limitCapture(s string) string {
	if len(s) > maxCaptureBytes {
		return s[:maxCaptureBytes] + "\n... [output truncated]"
	}
	return s
}

func isPermissionDenied(stderr string) bool {
	// Simple heuristic; callers may augment with more specific checks.
	return len(stderr) > 0 && (containsIgnoreCase(stderr, "permission denied") ||
		containsIgnoreCase(stderr, "access denied"))
}

func containsIgnoreCase(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	// quick lowercase match
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if lower(s[i+j]) != lower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
