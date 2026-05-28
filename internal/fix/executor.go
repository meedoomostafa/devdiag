package fix

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
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
				RefuseReason: proposal.BlockedReason,
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
					RefuseReason: "guarded fix requires --fresh or fresh scan",
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
						RefuseReason: "user declined confirmation",
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
					RefuseReason: "guarded fix requires interactive TTY",
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
				RefuseReason: "manual fix is not executable",
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

	cmd := exec.CommandContext(cmdCtx, bin, args...)
	stdoutBuf := cmdrunner.NewCappedBuffer(opts.CaptureCapBytes)
	stderrBuf := cmdrunner.NewCappedBuffer(opts.CaptureCapBytes)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	err := cmd.Run()
	execution.Stdout = redact(stdoutBuf.String())
	execution.Stderr = redact(stderrBuf.String())
	if err != nil {
		execution.Success = false
		if exitErr, ok := err.(*exec.ExitError); ok {
			execution.ExitCode = exitErr.ExitCode()
		} else {
			execution.ExitCode = -1
		}
		execution.Error = redact(err.Error())
	} else {
		execution.Success = true
		execution.ExitCode = 0
	}

	if e.audit != nil {
		_ = e.audit.Write(schema.FixAuditEntry{
			Timestamp: time.Now(),
			RunID:     proposal.RunID,
			FindingID: proposal.FindingID,
			HintID:    proposal.HintID,
			Class:     proposal.Class,
			Source:    proposal.Source,
			DryRun:    false,
			Execution: execution,
		})
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
