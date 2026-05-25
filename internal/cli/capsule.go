package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/capsule"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/redact"
	"github.com/meedoomostafa/devdiag/internal/repro"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var runIDAllowlist = regexp.MustCompile(`^[a-zA-Z0-9_:-]+$`)

func validateRunID(id string) error {
	if id == "" {
		return fmt.Errorf("run-id must not be empty")
	}
	if strings.Contains(id, string(filepath.Separator)) || strings.Contains(id, "/") {
		return fmt.Errorf("run-id must not contain path separators")
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("run-id must not contain path traversal sequences")
	}
	if !runIDAllowlist.MatchString(id) {
		return fmt.Errorf("run-id contains invalid characters (allowed: a-zA-Z0-9_:-)")
	}
	return nil
}

var capsuleRunID string

var capsuleCmd = &cobra.Command{
	Use:   "capsule",
	Short: "Create or inspect support capsules",
}

var capsuleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a redacted support capsule from a run artifact",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		redactEngine := buildRedactEngine()

		if flagRedact == "off" {
			logger.Warn("capsule", "redaction is disabled; secrets may be visible in the capsule")
		}

		// Resolve and validate run ID
		runID := capsuleRunID
		if runID != "" {
			if err := validateRunID(runID); err != nil {
				logger.Error("capsule", err.Error())
				return exitCodeError{code: exitcode.InvalidInput}
			}
		}
		if runID == "" {
			// Use latest run
			latest, err := findLatestRunID()
			if err != nil {
				logger.Error("capsule", fmt.Sprintf("no run ID specified and no runs found: %v", err))
				return exitCodeError{code: exitcode.InvalidInput}
			}
			runID = latest
			logger.Info("capsule", fmt.Sprintf("using latest run: %s", runID))
		}

		runsDir := filepath.Join(".devdiag", "runs", runID)
		if _, err := os.Stat(runsDir); os.IsNotExist(err) {
			logger.Error("capsule", fmt.Sprintf("run not found: %s", runsDir))
			return exitCodeError{code: exitcode.InvalidInput}
		}

		// Load report
		reportPath := filepath.Join(runsDir, "report.json")
		reportData, err := os.ReadFile(reportPath)
		if err != nil {
			logger.Error("capsule", fmt.Sprintf("read report: %v", err))
			return exitCodeError{code: exitcode.InvalidInput}
		}

		var report schema.Report
		if err := json.Unmarshal(reportData, &report); err != nil {
			logger.Error("capsule", fmt.Sprintf("parse report: %v", err))
			return exitCodeError{code: exitcode.InvalidInput}
		}

		// Load repro result if present
		var reproResult *repro.ReproResult
		reproPath := filepath.Join(runsDir, "repro.json")
		if reproData, err := os.ReadFile(reproPath); err == nil {
			var r repro.ReproResult
			if err := json.Unmarshal(reproData, &r); err == nil {
				reproResult = &r
			}
		}

		reportForCapsule := redactEngine.RedactReport(&report)
		var reproForCapsule *repro.ReproResult
		if reproResult != nil {
			reproForCapsule = redactReproResult(reproResult, redactEngine)
		}

		// Build capsule
		outPath := fmt.Sprintf("support-%s.devdiag.tgz", runID)
		outFile, err := os.Create(outPath)
		if err != nil {
			logger.Error("capsule", fmt.Sprintf("create output: %v", err))
			return exitCodeError{code: exitcode.InternalError}
		}
		defer outFile.Close()

		builder := capsule.NewBuilder(string(redactEngine.Level), version.Version)
		addCapsuleCommandLog(builder, runsDir, "command.stdout.log", redactEngine)
		addCapsuleCommandLog(builder, runsDir, "command.stderr.log", redactEngine)
		tracePath := filepath.Join(runsDir, "trace-result.json")
		if traceData, err := os.ReadFile(tracePath); err == nil {
			builder.SetTraceArtifact(traceData)
		}
		if err := builder.Build(outFile, reportForCapsule, reproForCapsule); err != nil {
			logger.Error("capsule", fmt.Sprintf("build failed: %v", err))
			return exitCodeError{code: exitcode.InternalError}
		}

		logger.Info("capsule", fmt.Sprintf("created %s", outPath))
		return renderCapsuleCreate(cmd, runID, outPath, string(redactEngine.Level))
	},
}

func addCapsuleCommandLog(builder *capsule.Builder, runsDir, name string, engine *redact.Engine) {
	data, err := os.ReadFile(filepath.Join(runsDir, "logs", name))
	if err != nil {
		return
	}
	redacted := engine.RedactString(string(data), "capsule_log")
	builder.SetLogArtifact(name, []byte(redacted))
}

var capsuleInspectCmd = &cobra.Command{
	Use:   "inspect <file>",
	Short: "Inspect a capsule archive without extracting raw logs",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := capsule.Inspect(args[0])
		if err != nil {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		return renderCapsuleInspect(cmd, result)
	},
}

type capsuleCreateResult struct {
	SchemaVersion   string `json:"schema_version"`
	DevDiagVersion  string `json:"devdiag_version"`
	RunID           string `json:"run_id"`
	RedactionStatus string `json:"redaction_status"`
	CapsulePath     string `json:"capsule_path"`
}

func renderCapsuleCreate(cmd *cobra.Command, runID, outPath, redactionStatus string) error {
	result := capsuleCreateResult{
		SchemaVersion:   schema.SchemaVersion,
		DevDiagVersion:  version.Version,
		RunID:           runID,
		RedactionStatus: redactionStatus,
		CapsulePath:     outPath,
	}
	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "ndjson":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	case "markdown":
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "# DevDiag Capsule\n\n- Run ID: `%s`\n- Capsule: `%s`\n- Redaction: `%s`\n", runID, outPath, redactionStatus)
		return err
	case "github":
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "### DevDiag capsule\n\nCreated `%s` for run `%s`.\n", outPath, runID)
		return err
	default:
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Capsule created: %s\n", outPath)
		return err
	}
}

func renderCapsuleInspect(cmd *cobra.Command, result *capsule.InspectResult) error {
	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "ndjson":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	case "markdown", "github":
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "```text\n%s```\n", result.Summary())
		return err
	default:
		_, err := fmt.Fprint(cmd.OutOrStdout(), result.Summary())
		return err
	}
}

func findLatestRunID() (string, error) {
	runsDir := filepath.Join(".devdiag", "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no runs found")
	}
	// Sort by name (which includes timestamp) and pick last
	sort.Slice(entries, func(i, j int) bool {
		return strings.Compare(entries[i].Name(), entries[j].Name()) < 0
	})
	latest := entries[len(entries)-1].Name()
	if err := validateRunID(latest); err != nil {
		return "", fmt.Errorf("latest run ID invalid: %w", err)
	}
	return latest, nil
}

func init() {
	capsuleCreateCmd.Flags().StringVar(&capsuleRunID, "run-id", "", "Run ID to package (defaults to latest)")
	capsuleCmd.AddCommand(capsuleCreateCmd)
	capsuleCmd.AddCommand(capsuleInspectCmd)
	rootCmd.AddCommand(capsuleCmd)
}
