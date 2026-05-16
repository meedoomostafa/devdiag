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
	upper := strings.ToUpper(key)
	// Exact or suffix matches for truly sensitive keys
	sensitive := []string{
		"PASSWORD", "SECRET", "TOKEN", "API_KEY", "AUTH_TOKEN", "CREDENTIAL",
		"DATABASE_URL", "PRIVATE_KEY", "ACCESS_KEY", "AWS_SECRET",
	}
	for _, s := range sensitive {
		if strings.Contains(upper, s) {
			return true
		}
	}
	// KEY alone is too broad (matches PATH, HOME); require it to be a standalone word or suffix
	if strings.Contains(upper, "_KEY") || strings.HasSuffix(upper, "KEY") {
		// Exclude common non-sensitive keys containing "KEY"
		if strings.Contains(upper, "PATH") || strings.Contains(upper, "HOME") ||
			strings.Contains(upper, "OLDPWD") || strings.Contains(upper, "XDG") ||
			strings.Contains(upper, "DESKTOP") || strings.Contains(upper, "SESSION") {
			return false
		}
		return true
	}
	return false
}

func redactString(s string) string {
	// Redact URL credentials: http://user:pass@host → http://<redacted>@host
	result := s
	for _, scheme := range []string{"http", "https", "ftp", "sftp", "postgres", "mysql", "redis", "mongodb"} {
		prefix := scheme + "://"
		for strings.Contains(result, prefix) {
			idx := strings.Index(result, prefix)
			end := strings.IndexAny(result[idx+len(prefix):], " /?#")
			if end == -1 {
				end = len(result) - idx - len(prefix)
			}
			segment := result[idx+len(prefix) : idx+len(prefix)+end]
			if at := strings.Index(segment, "@"); at > 0 {
				// Has credentials before @
				if colon := strings.Index(segment[:at], ":"); colon > 0 {
					// user:password@host
					result = result[:idx+len(prefix)] + "<redacted>" + result[idx+len(prefix)+at:]
				}
			}
			break
		}
	}

	// Redact JWT-like tokens (three base64url segments separated by dots)
	result = redactJWT(result)

	// Redact home directory paths
	home, _ := os.UserHomeDir()
	if home != "" {
		result = strings.ReplaceAll(result, home, "~")
	}

	return result
}

func redactJWT(s string) string {
	// Simple heuristic: look for eyJ... base64url JWT header pattern
	result := s
	for {
		idx := strings.Index(result, "eyJ")
		if idx == -1 {
			break
		}
		end := idx + 1
		for end < len(result) {
			c := result[end]
			if c == '.' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				end++
			} else {
				break
			}
		}
		token := result[idx:end]
		if strings.Count(token, ".") >= 2 && len(token) > 30 {
			result = result[:idx] + "<redacted-jwt>" + result[end:]
		} else {
			// Not a JWT, skip past eyJ
			result = result[:idx] + "xx" + result[idx+2:]
		}
	}
	return result
}
