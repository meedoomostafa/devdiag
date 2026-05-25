package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/capsule"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var (
	issueRunID       string
	issueCapsulePath string
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Generate team handoff artifacts from saved diagnostic runs",
}

var issueTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Generate a shareable issue template from a saved DevDiag run",
	RunE: func(cmd *cobra.Command, args []string) error {
		redactEngine := buildRedactEngine()

		runID := issueRunID
		if runID != "" {
			if err := validateRunID(runID); err != nil {
				return exitCodeError{code: exitcode.InvalidInput}
			}
		}
		if runID == "" {
			latest, err := findLatestRunID()
			if err != nil {
				return exitCodeError{code: exitcode.InvalidInput}
			}
			runID = latest
		}

		report, err := loadSavedReport(runID)
		if err != nil {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		if report.RunID == "" {
			report.RunID = runID
		}
		redactedReport := redactEngine.RedactReport(report)

		result := issueTemplateResult{
			SchemaVersion:  schema.SchemaVersion,
			DevDiagVersion: version.Version,
			RunID:          runID,
			Findings:       redactedReport.Findings,
		}

		if issueCapsulePath != "" {
			capsuleSummary, err := inspectIssueCapsule(issueCapsulePath, redactEngine.RedactString)
			if err != nil {
				return exitCodeError{code: exitcode.InvalidInput}
			}
			result.Capsule = capsuleSummary
		}

		result.Title = issueTitle(runID, redactedReport.Findings)
		result.Body = issueBody(runID, redactedReport.Findings, result.Capsule)
		return renderIssueTemplate(cmd, result)
	},
}

type issueTemplateResult struct {
	SchemaVersion  string               `json:"schema_version"`
	DevDiagVersion string               `json:"devdiag_version"`
	RunID          string               `json:"run_id"`
	Title          string               `json:"title"`
	Body           string               `json:"body"`
	Findings       []schema.Finding     `json:"findings"`
	Capsule        *issueCapsuleSummary `json:"capsule,omitempty"`
}

type issueCapsuleSummary struct {
	Path            string   `json:"path"`
	Valid           bool     `json:"valid"`
	FileCount       int      `json:"file_count"`
	RunID           string   `json:"run_id,omitempty"`
	RedactionStatus string   `json:"redaction_status,omitempty"`
	ReviewSummary   []string `json:"review_summary,omitempty"`
}

type pathRedactor func(string, string) string

func loadSavedReport(runID string) (*schema.Report, error) {
	reportPath := filepath.Join(".devdiag", "runs", runID, "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read saved report: %w", err)
	}
	var report schema.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse saved report: %w", err)
	}
	return &report, nil
}

func inspectIssueCapsule(path string, redact pathRedactor) (*issueCapsuleSummary, error) {
	inspect, err := capsule.Inspect(path)
	if err != nil {
		return nil, err
	}
	if !inspect.Valid {
		return nil, fmt.Errorf("capsule is not valid")
	}
	return &issueCapsuleSummary{
		Path:            redact(path, "capsule_path"),
		Valid:           inspect.Valid,
		FileCount:       inspect.FileCount,
		RunID:           inspect.RunID,
		RedactionStatus: inspect.RedactionStatus,
		ReviewSummary:   inspect.ReviewSummary,
	}, nil
}

func issueTitle(runID string, findings []schema.Finding) string {
	if len(findings) == 1 {
		return fmt.Sprintf("DevDiag: %s - %s", findings[0].ID, findings[0].Title)
	}
	if len(findings) == 0 {
		return "DevDiag: no findings for " + runID
	}
	return fmt.Sprintf("DevDiag: %d findings for %s", len(findings), runID)
}

func issueBody(runID string, findings []schema.Finding, capsuleSummary *issueCapsuleSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DevDiag issue: %s\n\n", runID)
	fmt.Fprintln(&b, "## Findings")
	if len(findings) == 0 {
		fmt.Fprintln(&b, "- No findings were recorded.")
	} else {
		for _, finding := range findings {
			fmt.Fprintf(&b, "- [%s] %s: %s\n", finding.Severity, finding.ID, finding.Title)
			if finding.Symptom != "" {
				fmt.Fprintf(&b, "  Symptom: %s\n", finding.Symptom)
			}
		}
	}
	if capsuleSummary != nil {
		fmt.Fprintln(&b, "\n## Capsule")
		fmt.Fprintf(&b, "- Path: `%s`\n", capsuleSummary.Path)
		fmt.Fprintf(&b, "- Run ID: `%s`\n", capsuleSummary.RunID)
		fmt.Fprintf(&b, "- Redaction: `%s`\n", capsuleSummary.RedactionStatus)
		fmt.Fprintf(&b, "- Files: `%d`\n", capsuleSummary.FileCount)
	}
	return b.String()
}

func renderIssueTemplate(cmd *cobra.Command, result issueTemplateResult) error {
	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "ndjson":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	default:
		_, err := fmt.Fprint(cmd.OutOrStdout(), result.Body)
		return err
	}
}

func init() {
	issueTemplateCmd.Flags().StringVar(&issueRunID, "run-id", "", "Saved run ID to read from .devdiag/runs")
	issueTemplateCmd.Flags().StringVar(&issueCapsulePath, "capsule", "", "Optional capsule archive to summarize")
	issueCmd.AddCommand(issueTemplateCmd)
	rootCmd.AddCommand(issueCmd)
}
