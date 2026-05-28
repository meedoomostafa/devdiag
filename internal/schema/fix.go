package schema

import "time"

// FixClass describes the safety level of a proposed fix.
type FixClass string

const (
	FixSafe    FixClass = "safe"
	FixGuarded FixClass = "guarded"
	FixManual  FixClass = "manual"
	FixBlocked FixClass = "blocked"
)

// Fix represents a single remediation option.
type Fix struct {
	Class    FixClass `json:"class"`
	Title    string   `json:"title"`
	Commands []string `json:"commands,omitempty"`
	Rollback []string `json:"rollback,omitempty"`
}

// FixSource indicates where the fix proposal originated.
type FixSource string

const (
	FixSourceSavedReport FixSource = "saved_report"
	FixSourceFreshScan   FixSource = "fresh_scan"
)

// FixProposal is a concrete remediation plan for a finding.
type FixProposal struct {
	FindingID        string    `json:"finding_id"`
	HintID           string    `json:"hint_id"`
	Title            string    `json:"title"`
	Class            FixClass  `json:"class"`
	Bin              string    `json:"bin,omitempty"`
	Args             []string  `json:"args,omitempty"`
	Rollback         []string  `json:"rollback,omitempty"`
	ConfirmMessage   string    `json:"confirm_message,omitempty"`
	BlockedReason    string    `json:"blocked_reason,omitempty"`
	RequiredEvidence []string  `json:"required_evidence,omitempty"`
	Source           FixSource `json:"source"`
	RunID            string    `json:"run_id,omitempty"`
	StalenessWarn    string    `json:"staleness_warn,omitempty"`
}

// FixExecution records the result of applying a fix.
type FixExecution struct {
	FindingID string    `json:"finding_id"`
	HintID    string    `json:"hint_id"`
	AppliedAt time.Time `json:"applied_at"`
	Success   bool      `json:"success"`
	ExitCode  int       `json:"exit_code"`
	Stdout    string    `json:"stdout,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// FixAuditEntry is a single line in the audit log.
type FixAuditEntry struct {
	Timestamp    time.Time     `json:"timestamp"`
	RunID        string        `json:"run_id"`
	FindingID    string        `json:"finding_id"`
	HintID       string        `json:"hint_id"`
	Class        FixClass      `json:"class"`
	Source       FixSource     `json:"source"`
	DryRun       bool          `json:"dry_run"`
	Execution    *FixExecution `json:"execution,omitempty"`
	Refused      bool          `json:"refused,omitempty"`
	RefuseReason string        `json:"refuse_reason,omitempty"`
	Note         string        `json:"note,omitempty"`
}
