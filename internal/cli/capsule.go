package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/capsule"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/repro"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

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

		// Resolve run ID
		runID := capsuleRunID
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

		// Build capsule
		outPath := fmt.Sprintf("support-%s.devdiag.tgz", runID)
		outFile, err := os.Create(outPath)
		if err != nil {
			logger.Error("capsule", fmt.Sprintf("create output: %v", err))
			return exitCodeError{code: exitcode.InternalError}
		}
		defer outFile.Close()

		builder := capsule.NewBuilder(string(redactEngine.Level), version.Version)
		if err := builder.Build(outFile, &report, reproResult); err != nil {
			logger.Error("capsule", fmt.Sprintf("build failed: %v", err))
			return exitCodeError{code: exitcode.InternalError}
		}

		logger.Info("capsule", fmt.Sprintf("created %s", outPath))
		fmt.Fprintf(cmd.OutOrStdout(), "Capsule created: %s\n", outPath)
		return nil
	},
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
		fmt.Fprint(cmd.OutOrStdout(), result.Summary())
		return nil
	},
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
	return entries[len(entries)-1].Name(), nil
}

func init() {
	capsuleCreateCmd.Flags().StringVar(&capsuleRunID, "run-id", "", "Run ID to package (defaults to latest)")
	capsuleCmd.AddCommand(capsuleCreateCmd)
	capsuleCmd.AddCommand(capsuleInspectCmd)
	rootCmd.AddCommand(capsuleCmd)
}
