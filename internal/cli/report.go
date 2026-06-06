package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/relevance"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	reportLatest bool
	reportRunID  string
	reportPath   string
)

var reportCmd = &cobra.Command{
	Use:   "report [path]",
	Short: "Render previously saved DevDiag reports without running a new scan",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		flagCount := countSourceFlags(reportLatest, reportRunID, reportPath)
		if flagCount == 0 {
			return exitCodeError{
				code:    exitcode.InvalidInput,
				message: "exactly one of --latest, --run-id, or --report must be provided",
			}
		}
		if flagCount > 1 {
			return exitCodeError{
				code:    exitcode.InvalidInput,
				message: "flags --latest, --run-id, and --report are mutually exclusive",
			}
		}

		var rep *schema.Report
		var err error

		if reportPath != "" {
			if len(args) > 0 {
				return exitCodeError{
					code:    exitcode.InvalidInput,
					message: "--report and [path] cannot be combined",
				}
			}
			rep, err = loadReportFile(reportPath)
			if err != nil {
				logger.Error("report", err.Error())
				return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
			}
		} else {
			startPath := "."
			if len(args) > 0 {
				startPath = args[0]
			}
			base, err := artifact.DiscoverBase(startPath)
			if err != nil {
				base = startPath
			}

			if reportRunID != "" {
				rep, err = resolveReportFromRunID(base, reportRunID)
				if err != nil {
					logger.Error("report", err.Error())
					return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
				}
			} else if reportLatest {
				var latestID string
				rep, latestID, err = resolveLatestReport(base)
				if err != nil {
					logger.Error("report", err.Error())
					return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
				}
				logger.Info("report", fmt.Sprintf("resolved latest report for run: %s", latestID))
			}
		}

		// Apply redaction defensively even for loaded reports
		redacted := redactEngine.RedactReport(rep)

		// Filter using relevance rules, including --include-hidden
		filtered, relevanceSummary := relevance.FilterReport(redacted, relevance.PolicyFromReport(redacted, flagIncludeHidden))

		// Render the filtered report
		renderer := pickRenderer(colorMode)
		if humanRenderer, ok := renderer.(*output.HumanRenderer); ok {
			humanRenderer.HiddenCount = relevanceSummary.Hidden
		}
		if mdRenderer, ok := renderer.(*output.MarkdownRenderer); ok {
			mdRenderer.HiddenCount = relevanceSummary.Hidden
		}
		if err := renderer.Render(filtered, cmd.OutOrStdout()); err != nil {
			return err
		}

		// Exit code is based on visible findings and fail-severity rules
		code := exitCodeFromResultsForCommand(cmd, filtered.Findings, filtered.Collectors, false)
		if code != exitcode.Success {
			return exitCodeError{code: code}
		}
		return nil
	},
}

func init() {
	reportCmd.Flags().BoolVar(&reportLatest, "latest", false, "Load the latest saved run report")
	reportCmd.Flags().StringVar(&reportRunID, "run-id", "", "Load a saved run report by ID")
	reportCmd.Flags().StringVar(&reportPath, "report", "", "Load a saved report JSON file path directly")
	rootCmd.AddCommand(reportCmd)
}
