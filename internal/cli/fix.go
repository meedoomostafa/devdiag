package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/fix"
	"github.com/meedoomostafa/devdiag/internal/logging"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"golang.org/x/term"
)

var (
	fixRunID     string
	fixApply     bool
	fixDryRun    bool
	fixFresh     bool
	fixHint      string
	fixList      bool
	fixTemplates bool
	fixCI        bool
	fixRulePack  string
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
	redactEngine := buildRedactEngine()
	planner := fix.NewPlanner()
	executor := fix.NewExecutor(fix.DefaultAuditLog())

	// Resolve and optionally scan
	report, source, runID, reportAge, err := resolveReportWithFresh(cmd, logger)
	if err != nil {
		logger.Error("fix", fmt.Sprintf("cannot resolve report: %v", err))
		return exitCodeError{code: exitcode.CollectorPartial}
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

	if fixHint != "" {
		proposals = filterProposalsByHint(proposals, fixHint)
		if len(proposals) == 0 {
			logger.Error("fix", fmt.Sprintf("no fix proposal for finding %s matches --hint %s", findingID, fixHint))
			return exitCodeError{code: exitcode.InvalidInput}
		}
	}

	// Render proposals
	renderer := pickFixRenderer(colorMode)
	if err := renderer.Render(proposals, cmd.OutOrStdout()); err != nil {
		return err
	}

	if fixApply && fixHint == "" && len(proposals) > 1 {
		logger.Error("fix", fmt.Sprintf("multiple fix proposals available for %s; rerun with --hint <hint-id>", findingID))
		return exitCodeError{code: exitcode.UnsafeRefused}
	}

	refused := false
	internalErr := false
	// Apply if requested
	if fixApply {
		for _, p := range proposals {
			_, err := executor.Execute(cmd.Context(), p, fix.ExecutorOptions{
				Apply:       true,
				Fresh:       fixFresh,
				Interactive: isTTY(),
				Redact:      func(s string) string { return redactEngine.RedactString(s, "fix_output") },
			})
			if err != nil {
				logger.Error("fix", fmt.Sprintf("apply failed for %s: %v", p.HintID, err))
				switch p.Class {
				case schema.FixBlocked, schema.FixManual, schema.FixGuarded:
					refused = true
				default:
					internalErr = true
				}
			}
		}
	}

	code := exitCodeFromFixResults(true, refused, internalErr)
	if code != exitcode.Success {
		return exitCodeError{code: code}
	}
	return nil
}

func filterProposalsByHint(proposals []schema.FixProposal, hint string) []schema.FixProposal {
	filtered := make([]schema.FixProposal, 0, len(proposals))
	for _, proposal := range proposals {
		if proposal.HintID == hint {
			filtered = append(filtered, proposal)
		}
	}
	return filtered
}

func runFixList(cmd *cobra.Command, logger *logging.Logger, colorMode output.ColorMode) error {
	planner := fix.NewPlanner()

	report, source, runID, reportAge, err := resolveReportWithFresh(cmd, logger)
	if err != nil {
		logger.Error("fix", fmt.Sprintf("cannot resolve report: %v", err))
		return exitCodeError{code: exitcode.CollectorPartial}
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
			Bin:              t.Bin,
			Args:             t.Args,
			Rollback:         t.Rollback,
			ConfirmMessage:   t.ConfirmMessage,
			BlockedReason:    t.BlockedReason,
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

// resolveReportWithFresh resolves the report and optionally runs a fresh scan.
func resolveReportWithFresh(cmd *cobra.Command, logger *logging.Logger) (*schema.Report, schema.FixSource, string, time.Duration, error) {
	base, err := artifact.DiscoverBase(".")
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("no saved report found; run 'devdiag scan --save-report' first")
	}

	if fixFresh {
		logger.Info("fix", "running fresh scan before planning")
		report, err := app.Scan(cmd.Context(), app.ScanOptions{
			Path:         base,
			Profile:      flagProfile,
			RulePackPath: fixRulePack,
			RedactLevel:  flagRedact,
			CI:           fixCI,
		}, app.NoopSink{})
		if err != nil {
			return nil, "", "", 0, fmt.Errorf("fresh scan failed: %w", err)
		}
		return report, schema.FixSourceFreshScan, report.RunID, 0, nil
	}

	return resolveReport()
}

// resolveReport loads the latest saved report or returns an error.
func resolveReport() (*schema.Report, schema.FixSource, string, time.Duration, error) {
	base, err := artifact.DiscoverBase(".")
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("no saved report found; run 'devdiag scan --save-report' first")
	}

	runID := fixRunID
	if runID == "" {
		latest, err := artifact.FindLatestRunID(base)
		if err != nil {
			return nil, "", "", 0, fmt.Errorf("no saved report found: %w", err)
		}
		runID = latest
	}

	runsDir := artifact.RunDir(base, runID)
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
	if stat.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func init() {
	fixCmd.Flags().StringVar(&fixRunID, "run-id", "", "Run ID to use (defaults to latest)")
	fixCmd.Flags().BoolVar(&fixApply, "apply", false, "Apply fix proposals")
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Show fix proposals without applying (default)")
	fixCmd.Flags().BoolVar(&fixFresh, "fresh", false, "Force fresh validation before applying")
	fixCmd.Flags().StringVar(&fixHint, "hint", "", "Fix hint ID to apply when a finding has multiple proposals")
	fixCmd.Flags().BoolVar(&fixList, "list", false, "List all fix proposals from report")
	fixCmd.Flags().BoolVar(&fixTemplates, "templates", false, "List registry templates")
	fixCmd.Flags().BoolVar(&fixCI, "ci", false, "Force CI/local parity collection and evaluation for fresh scan")
	fixCmd.Flags().StringVar(&fixRulePack, "rule-pack", "", "Evaluate an external deterministic rule pack for fresh scan")
	rootCmd.AddCommand(fixCmd)
}
