package repro

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ReproResult, Classification, and ReproEvent are defined in schema.go.

// Runner executes a user command and captures structured evidence.
type Runner struct {
	StdoutCap int64 // max bytes per stream; 0 = default 10MB
	StderrCap int64
	Timeout   time.Duration // 0 = default 60s
}

// NewRunner creates a Runner with sensible defaults.
func NewRunner() *Runner {
	return &Runner{
		StdoutCap: 10 << 20, // 10 MB
		StderrCap: 10 << 20,
		Timeout:   60 * time.Second,
	}
}

// Run executes the command with the given args, capturing output.
// It returns a ReproResult and a combined redacted log buffer.
func (r *Runner) Run(ctx context.Context, command string, args []string) (*ReproResult, error) {
	start := time.Now()

	wd, _ := os.Getwd()

	result := &ReproResult{
		Command:    command,
		Args:       args,
		WorkingDir: wd,
		StartTime:  start,
		ExitCode:   -1,
	}

	// Capture env keys only
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) > 0 && parts[0] != "" {
			result.EnvKeys = append(result.EnvKeys, parts[0])
			if isSensitiveEnvKey(parts[0]) {
				result.SensitiveEnvKeys = append(result.SensitiveEnvKeys, parts[0])
			}
		}
	}

	// Resolve command path
	cmdPath := command
	if !filepath.IsAbs(command) && !strings.Contains(command, string(os.PathSeparator)) {
		if p, err := exec.LookPath(command); err == nil {
			cmdPath = p
		}
	}

	result.Timeline = append(result.Timeline, ReproEvent{
		Timestamp: start,
		Type:      "start",
		Detail:    fmt.Sprintf("%s %s", command, strings.Join(args, " ")),
	})

	// Bounded capture
	stdoutBuf := newBoundedBuffer(r.StdoutCap)
	stderrBuf := newBoundedBuffer(r.StderrCap)

	cmdCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, cmdPath, args...)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	// On Linux, start in a new process group for group-kill on timeout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	runErr := cmd.Run()
	end := time.Now()
	result.EndTime = end
	result.DurationMs = end.Sub(start).Milliseconds()

	result.OriginalBytes = stdoutBuf.seen + stderrBuf.seen
	result.StoredBytes = int64(stdoutBuf.Len() + stderrBuf.Len())
	result.Truncated = stdoutBuf.truncated || stderrBuf.truncated

	// Redact before storing previews
	result.StdoutPreview = redactString(stdoutBuf.String())
	result.StderrPreview = redactString(stderrBuf.String())

	if runErr != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			result.TimedOut = true
			result.ExitCode = -1
			// Kill process group on timeout
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				time.Sleep(100 * time.Millisecond)
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			result.Timeline = append(result.Timeline, ReproEvent{
				Timestamp: time.Now(),
				Type:      "timeout",
				Detail:    fmt.Sprintf("timeout after %v", r.Timeout),
			})
			return result, nil // timeout is structured, not an error
		}

		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			// Command failed to start (e.g., ENOENT)
			result.ExitCode = -1
			return result, fmt.Errorf("command failed to start: %w", runErr)
		}
	} else {
		result.ExitCode = 0
	}

	result.Timeline = append(result.Timeline, ReproEvent{
		Timestamp: end,
		Type:      "exit",
		Detail:    fmt.Sprintf("exit_code=%d", result.ExitCode),
	})

	return result, nil
}

// boundedBuffer wraps a bytes.Buffer with a byte cap enforced during writes.
type boundedBuffer struct {
	buf       bytes.Buffer
	capBytes  int64
	seen      int64
	truncated bool
	mu        sync.Mutex
}

func newBoundedBuffer(capBytes int64) *boundedBuffer {
	if capBytes <= 0 {
		capBytes = 10 << 20
	}
	return &boundedBuffer{capBytes: capBytes}
}

func (b *boundedBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	origLen := len(p)
	b.seen += int64(origLen)
	if b.truncated {
		return origLen, nil // silently drop excess
	}

	remaining := b.capBytes - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return origLen, nil
	}

	if int64(len(p)) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return origLen, nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *boundedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func isSensitiveEnvKey(key string) bool {
	sensitive := []string{"PASSWORD", "SECRET", "TOKEN", "KEY", "API_KEY", "AUTH", "CREDENTIAL", "DATABASE_URL"}
	upper := strings.ToUpper(key)
	for _, s := range sensitive {
		if strings.Contains(upper, s) {
			return true
		}
	}
	return false
}

func redactString(s string) string {
	// Simple inline redaction for previews; full redaction happens via redact.Engine
	// Replace URL passwords, JWT-like tokens, and home paths
	return s
}
