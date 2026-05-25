package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/rulepack"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var teamRunID string

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Export team-review bundles from saved DevDiag runs",
}

var teamBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Export report, capsule, rule-pack, and issue-template metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		if teamRunID == "" {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		if err := validateRunID(teamRunID); err != nil {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		redactEngine := buildRedactEngine()
		report, err := loadSavedReport(teamRunID)
		if err != nil {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		if report.RunID == "" {
			report.RunID = teamRunID
		}
		redactedReport := redactEngine.RedactReport(report)

		var capsuleSummary *issueCapsuleSummary
		defaultCapsulePath := fmt.Sprintf("support-%s.devdiag.tgz", teamRunID)
		if _, err := os.Stat(defaultCapsulePath); err == nil {
			summary, err := inspectIssueCapsule(defaultCapsulePath, redactEngine.RedactString)
			if err != nil {
				return exitCodeError{code: exitcode.InvalidInput}
			}
			capsuleSummary = summary
		}

		issue := issueTemplateResult{
			SchemaVersion:  schema.SchemaVersion,
			DevDiagVersion: version.Version,
			RunID:          teamRunID,
			Findings:       redactedReport.Findings,
			Capsule:        capsuleSummary,
		}
		issue.Title = issueTitle(teamRunID, redactedReport.Findings)
		issue.Body = issueBody(teamRunID, redactedReport.Findings, capsuleSummary)

		result := teamBundleResult{
			SchemaVersion:   schema.SchemaVersion,
			DevDiagVersion:  version.Version,
			RunID:           teamRunID,
			RedactionStatus: redactedReport.RedactionStatus,
			Report: teamReportMetadata{
				SchemaVersion:   redactedReport.SchemaVersion,
				DevDiagVersion:  redactedReport.DevDiagVersion,
				RunID:           redactedReport.RunID,
				RedactionStatus: redactedReport.RedactionStatus,
				FindingCount:    len(redactedReport.Findings),
				CollectorCount:  len(redactedReport.Collectors),
			},
			Capsule:       capsuleSummary,
			RulePacks:     rulepack.BuiltInPacks(),
			IssueTemplate: issue,
			StableOutputs: []string{
				"report.findings",
				"devdiag rules packs --format json",
				"devdiag capsule inspect <file> --format json",
				"devdiag team bundle --run-id <id> --format json",
			},
			ExitCodes: documentedExitCodes(),
		}
		return renderTeamBundle(cmd, result)
	},
}

type teamBundleResult struct {
	SchemaVersion   string               `json:"schema_version"`
	DevDiagVersion  string               `json:"devdiag_version"`
	RunID           string               `json:"run_id"`
	RedactionStatus string               `json:"redaction_status"`
	Report          teamReportMetadata   `json:"report"`
	Capsule         *issueCapsuleSummary `json:"capsule,omitempty"`
	RulePacks       []rulepack.Pack      `json:"rule_packs"`
	IssueTemplate   issueTemplateResult  `json:"issue_template"`
	StableOutputs   []string             `json:"stable_outputs"`
	ExitCodes       map[string]int       `json:"exit_codes"`
}

type teamReportMetadata struct {
	SchemaVersion   string `json:"schema_version"`
	DevDiagVersion  string `json:"devdiag_version"`
	RunID           string `json:"run_id"`
	RedactionStatus string `json:"redaction_status"`
	FindingCount    int    `json:"finding_count"`
	CollectorCount  int    `json:"collector_count"`
}

func documentedExitCodes() map[string]int {
	return map[string]int{
		"success":           exitcode.Success.Int(),
		"findings_exist":    exitcode.FindingsExist.Int(),
		"invalid_input":     exitcode.InvalidInput.Int(),
		"collector_partial": exitcode.CollectorPartial.Int(),
		"permission_denied": exitcode.PermissionDenied.Int(),
		"unsafe_refused":    exitcode.UnsafeRefused.Int(),
		"repro_failed":      exitcode.ReproFailed.Int(),
		"trace_unavailable": exitcode.TraceUnavailable.Int(),
		"internal_error":    exitcode.InternalError.Int(),
	}
}

func renderTeamBundle(cmd *cobra.Command, result teamBundleResult) error {
	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "ndjson":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	default:
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "DevDiag team bundle: run_id=%s findings=%d redaction=%s\n", result.RunID, result.Report.FindingCount, result.RedactionStatus)
		return err
	}
}

func init() {
	teamBundleCmd.Flags().StringVar(&teamRunID, "run-id", "", "Saved run ID to bundle from .devdiag/runs")
	teamCmd.AddCommand(teamBundleCmd)
	rootCmd.AddCommand(teamCmd)
}
