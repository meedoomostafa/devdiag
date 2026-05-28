package cli

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/tui"
)

var inspectSaveReport bool
var inspectCI bool
var inspectRulePackPath string

var inspectCmd = &cobra.Command{
	Use:     "inspect [path]",
	Aliases: []string{"tui"},
	Short:   "Interactively inspect ranked findings and evidence",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runInspect,
}

func runInspect(cmd *cobra.Command, args []string) error {
	// Require a TTY for the interactive inspect workflow.
	if !output.IsTTY(os.Stdout) || !output.IsTTY(os.Stdin) {
		return exitCodeError{code: exitcode.InvalidInput}
	}

	logger := buildLogger()

	if flagRedact == "off" {
		logger.Warn("inspect", "redaction is disabled; secrets may be visible")
	}

	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		absPath = scanPath
	}

	logger.Info("inspect", fmt.Sprintf("scanning path=%s", absPath))

	opts := app.ScanOptions{
		Path:         absPath,
		Profile:      flagProfile,
		RulePackPath: inspectRulePackPath,
		RedactLevel:  flagRedact,
		CI:           inspectCI,
	}

	// Non-interactive parts (rule pack validation) may fail before TUI starts.
	// We let the TUI handle scan errors; pre-flight validation is limited
	// to what the CLI layer already enforces via PersistentPreRunE.

	model := tui.NewModel(opts, buildRedactEngine())
	p := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

		// After the TUI exits, optionally persist the report if requested.
	// The TUI model itself does not own persistence; the CLI layer does.
	if inspectSaveReport {
		if m, ok := finalModel.(tui.Model); ok && m.Report() != nil {
			// Redact the final report using the same engine before persisting.
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
	rootCmd.AddCommand(inspectCmd)
}
