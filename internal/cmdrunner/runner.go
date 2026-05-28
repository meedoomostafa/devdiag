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
	StdoutTruncated  bool
	StderrTruncated  bool
}

// CommandRunner abstracts external command execution for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) Result
}

// RunOptions carries optional execution settings for callers that need a
// working directory or stdin without bypassing CommandRunner.
type RunOptions struct {
	Dir           string
	Stdin         []byte
	StdoutCapBytes int
	StderrCapBytes int
}

// OptionRunner is implemented by runners that support RunOptions.
type OptionRunner interface {
	RunWithOptions(ctx context.Context, opts RunOptions, name string, args ...string) Result
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
	return r.RunWithOptions(ctx, RunOptions{}, name, args...)
}

// RunWithOptions executes the named command with optional directory/stdin settings.
func (r *RealRunner) RunWithOptions(ctx context.Context, opts RunOptions, name string, args ...string) Result {
	start := time.Now()
	res := Result{
		Command: name,
		Args:    append([]string(nil), args...),
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = opts.Dir
	if opts.Stdin != nil {
		cmd.Stdin = bytes.NewReader(opts.Stdin)
	} else {
		cmd.Stdin = nil
	}

	stdoutBuf := NewCappedBuffer(opts.StdoutCapBytes)
	stderrBuf := NewCappedBuffer(opts.StderrCapBytes)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	err := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = stdoutBuf.String()
	res.Stderr = stderrBuf.String()
	res.StdoutTruncated = stdoutBuf.Truncated()
	res.StderrTruncated = stderrBuf.Truncated()

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

// RunWithOptions executes through r with options when supported, otherwise it
// falls back to plain Run. Production callers should pass NewRealRunner, which
// supports options.
func RunWithOptions(ctx context.Context, r CommandRunner, opts RunOptions, name string, args ...string) Result {
	if r == nil {
		r = NewRealRunner()
	}
	if optionRunner, ok := r.(OptionRunner); ok {
		return optionRunner.RunWithOptions(ctx, opts, name, args...)
	}
	return r.Run(ctx, name, args...)
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
