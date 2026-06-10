package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/baseline"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/relevance"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var scanSaveReport bool
var scanCI bool
var scanRulePackPath string
var scanBaselinePath string
var scanNoBaseline bool

// scanCmd is a thin wrapper around app.Scan.
// Orchestration lives in internal/app; the CLI layer owns flags, rendering,
// exit-code mapping, and explicit artifact persistence.
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run a diagnostic scan on the given path",
	Example: `  devdiag scan .
  devdiag scan . --baseline ./ci/baseline.yaml
  devdiag scan . --no-baseline
  devdiag scan . --include-hidden`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if scanBaselinePath != "" && scanNoBaseline {
			return exitCodeError{code: exitcode.InvalidInput, message: "flags --baseline and --no-baseline are mutually exclusive"}
		}

		if flagRedact == "off" {
			logger.Warn("redact", "redaction is disabled; secrets may be visible")
		}

		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		absPath, err := resolveExistingDirectory(scanPath)
		if err != nil {
			logger.Error("scan", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
		}

		var loadedBaseline *baseline.Baseline
		if !scanNoBaseline {
			explicit := scanBaselinePath != ""
			var baselinePath string
			if explicit {
				var err error
				baselinePath, err = filepath.Abs(scanBaselinePath)
				if err != nil {
					return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
				}
			} else {
				baselinePath = baseline.DefaultPath(absPath)
			}
			loadedBaseline, err = loadBaselineForCommand(baselinePath, explicit)
			if err != nil {
				logger.Error("baseline", err.Error())
				return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("load baseline: %v", err)}
			}
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

		redacted := redactEngine.RedactReport(report)
		policy := relevance.PolicyFromReport(redacted, flagIncludeHidden)
		applyViewPolicy(&policy)

		if loadedBaseline != nil {
			relevance.ApplyBaseline(&policy, loadedBaseline, time.Now())
		}

		filtered, summary := relevance.FilterReport(redacted, policy)
		renderer := pickRenderer(colorMode)
		if humanRenderer, ok := renderer.(*output.HumanRenderer); ok {
			humanRenderer.HiddenCount = summary.Hidden
		}
		if mdRenderer, ok := renderer.(*output.MarkdownRenderer); ok {
			mdRenderer.HiddenCount = summary.Hidden
		}
		if err := renderer.Render(filtered, cmd.OutOrStdout()); err != nil {
			return err
		}

		// Persist reports only when explicitly requested. By default scan is read-only.
		if scanSaveReport {
			if err := persistReport(absPath, filtered); err != nil {
				logger.Warn("scan", fmt.Sprintf("failed to persist report: %v", err))
			}
		}

		code := exitCodeFromResultsForCommand(cmd, filtered.Findings, filtered.Collectors, false)
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
	scanCmd.Flags().StringVar(&scanBaselinePath, "baseline", "", "Path to custom baseline file (mutually exclusive with --no-baseline)")
	scanCmd.Flags().BoolVar(&scanNoBaseline, "no-baseline", false, "Disable baseline suppressions for the scan (mutually exclusive with --baseline)")
	rootCmd.AddCommand(scanCmd)
}
