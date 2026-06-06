package cli

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/tui"
)

var (
	inspectSaveReport   bool
	inspectCI           bool
	inspectRulePackPath string
	inspectLatest       bool
	inspectRunID        string
	inspectReportPath   string
)

var inspectCmd = &cobra.Command{
	Use:     "inspect [path]",
	Aliases: []string{"tui"},
	Short:   "Interactively inspect ranked findings and evidence",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runInspect,
}

type loadedInspectReport struct {
	report     *schema.Report
	mode       tui.ModelMode
	sourceName string
	basePath   string
}

func resolveInspectReport(args []string, latest bool, runID string, reportPath string) (*loadedInspectReport, error) {
	flagCount := countSourceFlags(latest, runID, reportPath)
	if flagCount > 1 {
		return nil, fmt.Errorf("flags --latest, --run-id, and --report are mutually exclusive")
	}

	if reportPath != "" {
		if len(args) > 0 {
			return nil, fmt.Errorf("--report and [path] cannot be combined")
		}
		rep, err := loadReportFile(reportPath)
		if err != nil {
			return nil, err
		}
		return &loadedInspectReport{
			report:     rep,
			mode:       tui.ModeReport,
			sourceName: reportPath,
			basePath:   ".",
		}, nil
	}

	if runID != "" {
		startPath := "."
		if len(args) > 0 {
			startPath = args[0]
		}
		base, err := artifact.DiscoverBase(startPath)
		if err != nil {
			base = startPath
		}
		rep, err := resolveReportFromRunID(base, runID)
		if err != nil {
			return nil, err
		}
		return &loadedInspectReport{
			report:     rep,
			mode:       tui.ModeRun,
			sourceName: runID,
			basePath:   base,
		}, nil
	}

	if latest {
		startPath := "."
		if len(args) > 0 {
			startPath = args[0]
		}
		base, err := artifact.DiscoverBase(startPath)
		if err != nil {
			base = startPath
		}
		rep, latestID, err := resolveLatestReport(base)
		if err != nil {
			return nil, err
		}
		return &loadedInspectReport{
			report:     rep,
			mode:       tui.ModeRun,
			sourceName: latestID,
			basePath:   base,
		}, nil
	}

	return nil, nil
}

func runInspect(cmd *cobra.Command, args []string) error {
	logger := buildLogger()

	loaded, err := resolveInspectReport(args, inspectLatest, inspectRunID, inspectReportPath)
	if err != nil {
		logger.Error("inspect", err.Error())
		return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
	}

	// Require a TTY for the interactive inspect workflow.
	if !output.IsTTY(os.Stdout) || !output.IsTTY(os.Stdin) {
		return exitCodeError{code: exitcode.InvalidInput}
	}

	if flagRedact == "off" {
		logger.Warn("inspect", "redaction is disabled; secrets may be visible")
	}

	var model tui.Model
	var absPath string

	if loaded != nil {
		absPath = loaded.basePath
		logger.Info("inspect", fmt.Sprintf("loading preloaded report mode=%v source=%s", loaded.mode, loaded.sourceName))
		model = tui.NewReportModel(loaded.report, loaded.sourceName, loaded.mode, buildRedactEngine(), flagIncludeHidden)
	} else {
		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		var err error
		absPath, err = resolveExistingDirectory(scanPath)
		if err != nil {
			logger.Error("inspect", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
		}

		logger.Info("inspect", fmt.Sprintf("scanning path=%s", absPath))

		opts := app.ScanOptions{
			Path:         absPath,
			Profile:      flagProfile,
			RulePackPath: inspectRulePackPath,
			RedactLevel:  flagRedact,
			CI:           inspectCI,
		}

		model = tui.NewScanModel(opts, buildRedactEngine(), flagIncludeHidden)
	}

	p := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// After the TUI exits, optionally persist the report if requested.
	if inspectSaveReport {
		if m, ok := finalModel.(tui.Model); ok && m.Report() != nil {
			redacted := buildRedactEngine().RedactReport(m.Report())
			if err := persistReport(absPath, redacted); err != nil {
				logger.Warn("inspect", fmt.Sprintf("failed to persist report: %v", err))
			}
		}
	}

	return nil
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectSaveReport, "save-report", false, "Persist report under .devdiag/runs for fix and capsule commands")
	inspectCmd.Flags().BoolVar(&inspectCI, "ci", false, "Force CI/local parity collection and evaluation")
	inspectCmd.Flags().StringVar(&inspectRulePackPath, "rule-pack", "", "Evaluate an external deterministic rule pack")
	inspectCmd.Flags().BoolVar(&inspectLatest, "latest", false, "Load the latest saved run report")
	inspectCmd.Flags().StringVar(&inspectRunID, "run-id", "", "Load a saved run report by ID")
	inspectCmd.Flags().StringVar(&inspectReportPath, "report", "", "Load a saved report JSON file path directly")
	rootCmd.AddCommand(inspectCmd)
}
