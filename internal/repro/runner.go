package repro

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/redact"
)

// ReproResult, Classification, and ReproEvent are defined in schema.go.

// Runner executes a user command and captures structured evidence.
type Runner struct {
	StdoutCap int64 // max bytes per stream; 0 = default 10MB
	StderrCap int64
	Timeout   time.Duration // 0 = default 60s
	Redactor  *redact.Engine
	// CmdRunner executes the command. Defaults to cmdrunner.NewRealRunner,
	// which starts commands in their own process group so timeouts kill
	// spawned children too. Injectable for tests.
	CmdRunner cmdrunner.CommandRunner
}

// NewRunner creates a Runner with sensible defaults.
func NewRunner() *Runner {
	return &Runner{
		StdoutCap: 10 << 20, // 10 MB
		StderrCap: 10 << 20,
		Timeout:   60 * time.Second,
		Redactor:  redact.NewEngine(redact.LevelDefault),
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

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runner := r.CmdRunner
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	res := cmdrunner.RunWithOptions(cmdCtx, runner, cmdrunner.RunOptions{
		StdoutCapBytes: int(r.StdoutCap),
		StderrCapBytes: int(r.StderrCap),
	}, cmdPath, args...)

	end := time.Now()
	result.EndTime = end
	result.DurationMs = end.Sub(start).Milliseconds()

	result.OriginalBytes = int64(res.StdoutSeenBytes + res.StderrSeenBytes)
	result.StoredBytes = int64(len(res.Stdout) + len(res.Stderr))
	result.Truncated = res.StdoutTruncated || res.StderrTruncated

	// Redact before storing previews via shared engine
	result.StdoutPreview = r.Redactor.RedactString(res.Stdout, "repro_stdout")
	result.StderrPreview = r.Redactor.RedactString(res.Stderr, "repro_stderr")

	if res.TimedOut {
		result.TimedOut = true
		result.ExitCode = -1
		result.Timeline = append(result.Timeline, ReproEvent{
			Timestamp: time.Now(),
			Type:      "timeout",
			Detail:    fmt.Sprintf("timeout after %v", timeout),
		})
		return result, nil // timeout is structured, not an error
	}
	if res.NotFound {
		result.ExitCode = -1
		return result, fmt.Errorf("command failed to start: %s not found", cmdPath)
	}
	result.ExitCode = res.ExitCode

	result.Timeline = append(result.Timeline, ReproEvent{
		Timestamp: end,
		Type:      "exit",
		Detail:    fmt.Sprintf("exit_code=%d", result.ExitCode),
	})

	return result, nil
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
