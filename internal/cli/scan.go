package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var scanSaveReport bool
var scanCI bool
var scanRulePackPath string

// scanCmd is a thin wrapper around app.Scan.
// Orchestration lives in internal/app; the CLI layer owns flags, rendering,
// exit-code mapping, and explicit artifact persistence.
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run a diagnostic scan on the given path",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if flagRedact == "off" {
			logger.Warn("redact", "redaction is disabled; secrets may be visible")
		}

		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		absPath, err := filepath.Abs(scanPath)
		if err != nil {
			absPath = scanPath
		}

		logger.Info("scan", fmt.Sprintf("scanning path=%s", absPath))

		ctx := cmd.Context()
		opts := app.ScanOptions{
			Path:         absPath,
			Profile:      flagProfile,
			RulePackPath: scanRulePackPath,
			RedactLevel:  flagRedact,
			CI:           scanCI,
		}

		report, err := app.Scan(ctx, opts, app.NoopSink{})
		if err != nil {
			var rpe *app.RulePackError
			if errors.As(err, &rpe) {
				logger.Error("rule-pack", strings.Join(rpe.Errors, "; "))
				return exitCodeError{code: exitcode.InvalidInput}
			}
			logger.Error("policy", err.Error())
			return fmt.Errorf("policy evaluation failed: %w", err)
		}

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return err
		}

				// Persist reports only when explicitly requested. By default scan is read-only.
		if scanSaveReport {
			if err := persistReport(absPath, redacted); err != nil {
				logger.Warn("scan", fmt.Sprintf("failed to persist report: %v", err))
			}
		}

		code := exitCodeFromResultsForCommand(cmd, report.Findings, report.Collectors, false)
		if code != exitcode.Success {
			return exitCodeError{code: code}
		}
		return nil
	},
}

func persistReport(base string, report *schema.Report) error {
	if base == "" {
		base = "."
	}
	runsDir := artifact.RunDir(base, report.RunID)
	if err := artifact.MkdirPrivate(runsDir); err != nil {
		return fmt.Errorf("create runs dir: %w", err)
	}
	reportPath := filepath.Join(runsDir, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := artifact.WriteFilePrivate(reportPath, data); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func init() {
	scanCmd.Flags().BoolVar(&scanSaveReport, "save-report", false, "Persist report under .devdiag/runs for fix and capsule commands")
	scanCmd.Flags().BoolVar(&scanCI, "ci", false, "Force CI/local parity collection and evaluation")
	scanCmd.Flags().StringVar(&scanRulePackPath, "rule-pack", "", "Evaluate an external deterministic rule pack")
	rootCmd.AddCommand(scanCmd)
}
