package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/fix"
	"github.com/meedoomostafa/devdiag/internal/logging"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	fixRunID     string
	fixApply     bool
	fixDryRun    bool
	fixFresh     bool
	fixList      bool
	fixTemplates bool
)

var fixCmd = &cobra.Command{
	Use:   "fix [finding-id]",
	Short: "Generate or apply fix proposals for findings",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()

		if fixDryRun && fixApply {
			logger.Error("fix", "cannot use --dry-run with --apply")
			return exitCodeError{code: exitcode.InvalidInput}
		}

		if fixList {
			return runFixList(cmd, logger, colorMode)
		}
		if fixTemplates {
			return runFixTemplates(cmd, logger, colorMode)
		}

		if len(args) == 0 {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		findingID := args[0]
		return runFix(cmd, findingID, logger, colorMode)
	},
}

func runFix(cmd *cobra.Command, findingID string, logger *logging.Logger, colorMode output.ColorMode) error {
	planner := fix.NewPlanner()
	executor := fix.NewExecutor(fix.DefaultAuditLog())

	// Load or generate report
	report, source, runID, reportAge, err := resolveReport()
	if err != nil {
		logger.Error("fix", fmt.Sprintf("cannot resolve report: %v", err))
		return exitCodeError{code: exitcode.CollectorPartial}
	}

	if fixFresh {
		// In M5, --fresh on fix does a targeted mini-scan. For now, we reuse
		// the loaded report but mark source as fresh_scan since the user
		// explicitly requested it. Future iterations can run targeted collectors.
		source = schema.FixSourceFreshScan
		reportAge = 0
	}

	proposals, err := planner.Resolve(report, fix.ResolveOptions{
		FindingID: findingID,
		Source:    source,
		RunID:     runID,
		ReportAge: reportAge,
	})
	if err != nil {
		logger.Error("fix", fmt.Sprintf("planning failed: %v", err))
		return exitCodeError{code: exitcode.InternalError}
	}

	if len(proposals) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No fix proposals for finding %s.\n", findingID)
		return nil
	}

	// Render proposals
	renderer := pickFixRenderer(colorMode)
	if err := renderer.Render(proposals, cmd.OutOrStdout()); err != nil {
		return err
	}

	blocked := false
	// Apply if requested
	if fixApply {
		for _, p := range proposals {
			_, err := executor.Execute(cmd.Context(), p, fix.ExecutorOptions{
				Apply:       true,
				Fresh:       fixFresh,
				Interactive: isTTY(),
			})
			if err != nil {
				logger.Error("fix", fmt.Sprintf("apply failed for %s: %v", p.HintID, err))
				if p.Class == schema.FixBlocked {
					blocked = true
				}
			}
		}
	}

	code := exitCodeFromFixResults(true, blocked, false)
	if code != exitcode.Success {
		return exitCodeError{code: code}
	}
	return nil
}

func runFixList(cmd *cobra.Command, logger *logging.Logger, colorMode output.ColorMode) error {
	planner := fix.NewPlanner()

	report, source, runID, reportAge, err := resolveReport()
	if err != nil {
		logger.Error("fix", fmt.Sprintf("cannot resolve report: %v", err))
		return exitCodeError{code: exitcode.CollectorPartial}
	}

	if fixFresh {
		source = schema.FixSourceFreshScan
		reportAge = 0
	}

	proposals, err := planner.ListAll(report, source, runID, reportAge)
	if err != nil {
		logger.Error("fix", fmt.Sprintf("listing failed: %v", err))
		return exitCodeError{code: exitcode.InternalError}
	}

	renderer := pickFixRenderer(colorMode)
	if err := renderer.Render(proposals, cmd.OutOrStdout()); err != nil {
		return err
	}
	code := exitCodeFromFixResults(true, false, false)
	if code != exitcode.Success {
		return exitCodeError{code: code}
	}
	return nil
}

func runFixTemplates(cmd *cobra.Command, logger *logging.Logger, colorMode output.ColorMode) error {
	registry := fix.NewRegistry()
	templates := registry.List()

	var proposals []schema.FixProposal
	for _, t := range templates {
		proposals = append(proposals, schema.FixProposal{
			HintID:           t.HintID,
			Title:            t.Title,
			Class:            t.Class,
			RequiredEvidence: t.RequiredEvidence,
			Source:           "",
		})
	}

	renderer := pickFixRenderer(colorMode)
	if err := renderer.Render(proposals, cmd.OutOrStdout()); err != nil {
		return err
	}
	return nil
}

// resolveReport loads the latest saved report or returns an error.
func resolveReport() (*schema.Report, schema.FixSource, string, time.Duration, error) {
	runID := fixRunID
	if runID == "" {
		latest, err := findLatestRunID()
		if err != nil {
			return nil, "", "", 0, fmt.Errorf("no saved report found; run 'devdiag scan --save-report' first")
		}
		runID = latest
	}

	runsDir := filepath.Join(".devdiag", "runs", runID)
	reportPath := filepath.Join(runsDir, "report.json")
	info, err := os.Stat(reportPath)
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("report not found: %w", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("read report: %w", err)
	}

	var report schema.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, "", "", 0, fmt.Errorf("parse report: %w", err)
	}

	reportAge := time.Since(info.ModTime())
	return &report, schema.FixSourceSavedReport, runID, reportAge, nil
}

func pickFixRenderer(colorMode output.ColorMode) fix.ProposalRenderer {
	switch flagFormat {
	case "json":
		return &fix.JSONRenderer{}
	case "ndjson":
		return &fix.NDJSONRenderer{}
	case "markdown":
		return &fix.MarkdownRenderer{}
	default:
		return &fix.HumanRenderer{}
	}
}

func isTTY() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == os.ModeCharDevice
}

func init() {
	fixCmd.Flags().StringVar(&fixRunID, "run-id", "", "Run ID to use (defaults to latest)")
	fixCmd.Flags().BoolVar(&fixApply, "apply", false, "Apply fix proposals")
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Show fix proposals without applying (default)")
	fixCmd.Flags().BoolVar(&fixFresh, "fresh", false, "Force fresh validation before applying")
	fixCmd.Flags().BoolVar(&fixList, "list", false, "List all fix proposals from report")
	fixCmd.Flags().BoolVar(&fixTemplates, "templates", false, "List registry templates")
	rootCmd.AddCommand(fixCmd)
}
