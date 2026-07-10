package trace

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	maxTraceEvents    = 10000
	maxTraceFileBytes = 50 * 1024 * 1024 // 50 MB
)

// Runner executes strace with scoped filters and parses output into Events.
type Runner struct {
	Timeout   time.Duration
	MaxEvents int
}

// Run starts strace for the given command, reads the trace file, and parses Events.
func (r *Runner) Run(ctx context.Context, scopes []Scope, command string, args ...string) (*Result, error) {
	if command == "" {
		return nil, fmt.Errorf("trace command is empty")
	}
	if r.Timeout == 0 {
		r.Timeout = 30 * time.Second
	}
	if r.MaxEvents == 0 {
		r.MaxEvents = maxTraceEvents
	}

	// Create temp trace file
	traceFile, err := os.CreateTemp("", "devdiag-trace-*.log")
	if err != nil {
		return nil, fmt.Errorf("create temp trace file: %w", err)
	}
	tracePath := traceFile.Name()
	traceFile.Close()
	defer os.Remove(tracePath)

	straceArgs := buildStraceArgs(scopes, tracePath, command, args)

	res := &Result{
		Command:          command,
		Args:             args,
		Scopes:           scopes,
		Backend:          "strace",
		Events:           make([]Event, 0, r.MaxEvents),
		SeccompRequested: true,
	}

	start := time.Now()
	cmdCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.Command("strace", straceArgs...)
	// Run strace and all tracees in their own process group so a timeout
	// kills the whole tree; killing only strace leaves tracees running.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	err = runWithGroupKill(cmdCtx, cmd)
	res.Duration = time.Since(start)
	stderr := stderrBuf.String()

	if isSeccompBPFDegraded(stderr) {
		markSeccompBPFDegraded(res)
	}

	if cmdCtx.Err() != nil {
		if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
			res.TimedOut = true
			res.Partial = true
			res.Notes = append(res.Notes, "trace timed out; child processes were signaled by command context")
		} else if errors.Is(cmdCtx.Err(), context.Canceled) {
			res.Canceled = true
			res.Partial = true
			res.Notes = append(res.Notes, "trace canceled by parent context")
		}
	}

	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				res.ProcessFailed = true
				res.Notes = append(res.Notes, fmt.Sprintf("traced process killed by signal %d (%s)", ws.Signal(), ws.Signal()))
			}
		}
	} else if err != nil {
		res.ExitCode = -1
	}

	if err != nil && !res.TimedOut && !res.Canceled {
		if stderr != "" {
			res.Notes = append(res.Notes, fmt.Sprintf("strace stderr: %s", strings.TrimSpace(stderr)))
		}
		// Detect ptrace/permission failures that make tracing unavailable
		if isTraceUnavailable(stderr) {
			res.TraceUnavailable = true
			res.UnavailableReason = "ptrace_permission_denied"
			res.Notes = append(res.Notes, "trace unavailable: ptrace/permission denied")
		} else if _, ok := err.(*exec.ExitError); ok {
			res.Notes = append(res.Notes, "strace or traced command exited non-zero")
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("strace could not start: %v", err))
		}
	}

	if res.SeccompRequested && !res.SeccompDegraded && !res.TraceUnavailable && (err == nil || cmd.ProcessState != nil) {
		res.SeccompApplied = true
	}

	// Read and parse trace file
	if err := r.readTraceFile(tracePath, res); err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("trace file read error: %v", err))
	}

	return res, nil
}

var traceUnavailablePatterns = []string{
	"operation not permitted",
	"ptrace_traceme",
	"permission denied",
	"strace: attach",
	"ptrace",
}

func isTraceUnavailable(stderr string) bool {
	lower := strings.ToLower(stderr)
	for _, p := range traceUnavailablePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isSeccompBPFDegraded(stderr string) bool {
	return strings.Contains(stderr, "strace: seccomp-bpf requested but not enabled")
}

func markSeccompBPFDegraded(res *Result) {
	res.SeccompRequested = true
	res.SeccompApplied = false
	res.SeccompDegraded = true
	res.Notes = append(res.Notes, "seccomp-bpf degraded: tracing fell back to full ptrace syscall stops; heavy commands such as npm install, cargo build, or large test suites can become dramatically slower")
}

// runWithGroupKill starts cmd and waits for it. When ctx expires it kills
// cmd's entire process group (SIGTERM, then SIGKILL) so tracees spawned by
// strace -f die with it.
func runWithGroupKill(ctx context.Context, cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		if cmd.Process != nil {
			pgid := -cmd.Process.Pid
			_ = syscall.Kill(pgid, syscall.SIGTERM)
			select {
			case err := <-waitCh:
				return err
			case <-time.After(100 * time.Millisecond):
				_ = syscall.Kill(pgid, syscall.SIGKILL)
				return <-waitCh
			}
		}
		return <-waitCh
	}
}

// buildStraceArgs builds the strace invocation. --kill-on-exit is not passed
// explicitly: strace >= 6.6 auto-activates it with --seccomp-bpf, and older
// versions reject the flag outright; orphan cleanup is guaranteed by the
// process-group kill in runWithGroupKill regardless of strace version.
func buildStraceArgs(scopes []Scope, tracePath, command string, args []string) []string {
	straceArgs := []string{"-f", "-tt", "-T", "-yy", "-o", tracePath, "--seccomp-bpf"}
	straceArgs = append(straceArgs, buildStraceFilters(scopes)...)
	straceArgs = append(straceArgs, "--", command)
	straceArgs = append(straceArgs, args...)
	return straceArgs
}

func buildStraceFilters(scopes []Scope) []string {
	groups := []string{}
	for _, s := range scopes {
		switch s {
		case ScopeFile:
			groups = append(groups, "%file")
		case ScopeProcess:
			groups = append(groups, "%process")
		case ScopeNetwork:
			groups = append(groups, "%network")
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return []string{"-e", fmt.Sprintf("trace=%s", strings.Join(groups, ","))}
}

func (r *Runner) readTraceFile(path string, res *Result) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > maxTraceFileBytes {
		res.Partial = true
		res.Notes = append(res.Notes, fmt.Sprintf("trace file exceeds %d bytes; parsing partial data", maxTraceFileBytes))
	}

	// Use LimitReader to cap input
	reader := io.LimitReader(f, maxTraceFileBytes)
	scanner := bufio.NewScanner(reader)
	// Increase max token size to 1MB
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	pending := make(map[pendingSyscall]string)
	notedSkippedPair := false

	for scanner.Scan() {
		if len(res.Events) >= r.MaxEvents {
			res.Partial = true
			res.Notes = append(res.Notes, fmt.Sprintf("reached max trace events (%d); stopping parse", r.MaxEvents))
			break
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		if key, partial, ok := parseUnfinishedTraceLine(line); ok {
			pending[key] = partial
			continue
		}
		if strings.Contains(line, "<... ") {
			merged, key, ok := mergeResumedTraceLine(line, pending)
			if !ok {
				res.Partial = true
				res.SkippedEvents++
				if !notedSkippedPair {
					res.Notes = append(res.Notes, "skipped unfinished/resumed syscall pair")
					notedSkippedPair = true
				}
				continue
			}
			delete(pending, key)
			line = merged
		}
		ev, err := ParseLine(line)
		if err != nil {
			// Skip non-event lines
			continue
		}
		res.Events = append(res.Events, *ev)
	}
	if len(pending) > 0 {
		res.Partial = true
		res.SkippedEvents += len(pending)
		if !notedSkippedPair {
			res.Notes = append(res.Notes, "skipped unfinished/resumed syscall pair")
		}
	}
	return scanner.Err()
}
