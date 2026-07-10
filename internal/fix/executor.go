package fix

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// ExecutorOptions controls execution behavior.
type ExecutorOptions struct {
	Apply           bool
	Fresh           bool
	Interactive     bool // true if stdin is a TTY
	Redact          func(string) string
	CaptureCapBytes int
}

// Executor applies fix proposals safely.
type Executor struct {
	audit *AuditLog
	// Runner executes fix commands. Defaults to cmdrunner.NewRealRunner,
	// which starts commands in their own process group so timeouts kill
	// spawned children too. Injectable for tests.
	Runner cmdrunner.CommandRunner
}

// NewExecutor creates an executor with the given audit log.
func NewExecutor(audit *AuditLog) *Executor {
	return &Executor{audit: audit}
}

// PreflightAudit checks if the audit log is writable before mutation.
func (e *Executor) PreflightAudit(proposal schema.FixProposal) error {
	if e.audit == nil {
		return nil
	}
	return e.audit.Write(schema.FixAuditEntry{
		Timestamp: time.Now(),
		RunID:     proposal.RunID,
		FindingID: proposal.FindingID,
		HintID:    proposal.HintID,
		Class:     proposal.Class,
		Source:    proposal.Source,
		Note:      "audit_preflight",
	})
}

// Execute runs a single fix proposal.
func (e *Executor) Execute(ctx context.Context, proposal schema.FixProposal, opts ExecutorOptions) (*schema.FixExecution, error) {
	redact := opts.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}

	// Always blocked
	if proposal.Class == schema.FixBlocked {
		if e.audit != nil {
			_ = e.audit.Write(schema.FixAuditEntry{
				Timestamp:    time.Now(),
				RunID:        proposal.RunID,
				FindingID:    proposal.FindingID,
				HintID:       proposal.HintID,
				Class:        proposal.Class,
				Source:       proposal.Source,
				DryRun:       !opts.Apply,
				Refused:      true,
				RefuseReason: redact(proposal.BlockedReason),
			})
		}
		return nil, fmt.Errorf("fix is blocked: %s", proposal.BlockedReason)
	}

	// Dry-run mode: do not execute
	if !opts.Apply {
		if e.audit != nil {
			_ = e.audit.Write(schema.FixAuditEntry{
				Timestamp: time.Now(),
				RunID:     proposal.RunID,
				FindingID: proposal.FindingID,
				HintID:    proposal.HintID,
				Class:     proposal.Class,
				Source:    proposal.Source,
				DryRun:    true,
			})
		}
		return nil, nil
	}

	// For apply operations, ensure audit is writable first.
	if err := e.PreflightAudit(proposal); err != nil {
		return nil, fmt.Errorf("audit log unavailable, refusing apply: %w", err)
	}

	// Guarded fixes require fresh validation and TTY confirmation
	if proposal.Class == schema.FixGuarded {
		if !opts.Fresh && proposal.Source == schema.FixSourceSavedReport {
			if e.audit != nil {
				_ = e.audit.Write(schema.FixAuditEntry{
					Timestamp:    time.Now(),
					RunID:        proposal.RunID,
					FindingID:    proposal.FindingID,
					HintID:       proposal.HintID,
					Class:        proposal.Class,
					Source:       proposal.Source,
					DryRun:       false,
					Refused:      true,
					RefuseReason: redact("guarded fix requires --fresh or fresh scan"),
				})
			}
			return nil, fmt.Errorf("guarded fix requires --fresh")
		}
		if opts.Interactive {
			if !confirmTTY(proposal) {
				if e.audit != nil {
					_ = e.audit.Write(schema.FixAuditEntry{
						Timestamp:    time.Now(),
						RunID:        proposal.RunID,
						FindingID:    proposal.FindingID,
						HintID:       proposal.HintID,
						Class:        proposal.Class,
						Source:       proposal.Source,
						DryRun:       false,
						Refused:      true,
						RefuseReason: redact("user declined confirmation"),
					})
				}
				return nil, fmt.Errorf("user declined confirmation")
			}
		} else {
			if e.audit != nil {
				_ = e.audit.Write(schema.FixAuditEntry{
					Timestamp:    time.Now(),
					RunID:        proposal.RunID,
					FindingID:    proposal.FindingID,
					HintID:       proposal.HintID,
					Class:        proposal.Class,
					Source:       proposal.Source,
					DryRun:       false,
					Refused:      true,
					RefuseReason: redact("guarded fix requires interactive TTY"),
				})
			}
			return nil, fmt.Errorf("guarded fix requires interactive TTY")
		}
	}

	// Manual fixes are never executed
	if proposal.Class == schema.FixManual {
		if e.audit != nil {
			_ = e.audit.Write(schema.FixAuditEntry{
				Timestamp:    time.Now(),
				RunID:        proposal.RunID,
				FindingID:    proposal.FindingID,
				HintID:       proposal.HintID,
				Class:        proposal.Class,
				Source:       proposal.Source,
				DryRun:       false,
				Refused:      true,
				RefuseReason: redact("manual fix is not executable"),
			})
		}
		return nil, fmt.Errorf("manual fix cannot be applied automatically")
	}

	// Safe fixes: execute with exec.CommandContext
	execution := &schema.FixExecution{
		FindingID: proposal.FindingID,
		HintID:    proposal.HintID,
		AppliedAt: time.Now(),
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	bin := proposal.Bin
	args := proposal.Args
	if bin == "" && len(args) > 0 {
		bin = args[0]
		args = args[1:]
	}
	if bin == "" {
		execution.Success = false
		execution.Error = "no command binary specified"
		return execution, fmt.Errorf("no command binary specified")
	}

	// Runtime defense-in-depth: blocklist check before execution
	if IsBlockedCommand(bin, args) {
		execution.Success = false
		execution.Error = "command matches runtime blocklist"
		return execution, fmt.Errorf("command matches runtime blocklist")
	}

	runner := e.Runner
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	res := cmdrunner.RunWithOptions(cmdCtx, runner, cmdrunner.RunOptions{
		StdoutCapBytes: opts.CaptureCapBytes,
		StderrCapBytes: opts.CaptureCapBytes,
	}, bin, args...)
	execution.Stdout = redact(res.Stdout)
	execution.Stderr = redact(res.Stderr)
	execution.ExitCode = res.ExitCode
	switch {
	case res.TimedOut:
		execution.Success = false
		execution.Error = "fix command timed out"
	case res.NotFound:
		execution.Success = false
		execution.Error = fmt.Sprintf("command not found: %s", bin)
	case res.PermissionDenied:
		execution.Success = false
		execution.Error = fmt.Sprintf("permission denied running %s", bin)
	case res.ExitCode != 0:
		execution.Success = false
		execution.Error = redact(fmt.Sprintf("command exited with code %d", res.ExitCode))
	default:
		execution.Success = true
	}

	if e.audit != nil {
		if err := e.audit.Write(schema.FixAuditEntry{
			Timestamp: time.Now(),
			RunID:     proposal.RunID,
			FindingID: proposal.FindingID,
			HintID:    proposal.HintID,
			Class:     proposal.Class,
			Source:    proposal.Source,
			DryRun:    false,
			Execution: execution,
		}); err != nil {
			msg := fmt.Sprintf("failed to write final audit entry: %v", err)
			if execution.Error != "" {
				execution.Error += "; " + msg
			} else {
				execution.Error = msg
			}
			execution.Success = false
		}
	}

	if !execution.Success {
		return execution, fmt.Errorf("fix execution failed: %s", execution.Error)
	}
	return execution, nil
}

func confirmTTY(proposal schema.FixProposal) bool {
	fmt.Fprintf(os.Stderr, "\nGuarded fix: %s\n", proposal.Title)
	if proposal.ConfirmMessage != "" {
		fmt.Fprintf(os.Stderr, "Risk: %s\n", proposal.ConfirmMessage)
	}
	fmt.Fprintf(os.Stderr, "Command: %s %s\n", proposal.Bin, strings.Join(proposal.Args, " "))
	if len(proposal.Rollback) > 0 {
		fmt.Fprintf(os.Stderr, "Rollback: %s\n", strings.Join(proposal.Rollback, " "))
	}
	fmt.Fprintf(os.Stderr, "Apply? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	resp = strings.TrimSpace(strings.ToLower(resp))
	return resp == "y" || resp == "yes"
}
