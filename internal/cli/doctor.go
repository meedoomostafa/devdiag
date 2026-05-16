package cli

import (
	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Validate DevDiag binary/config/runtime health",
}

var doctorSelfCmd = &cobra.Command{
	Use:   "self",
	Short: "Validate DevDiag binary/config/runtime health",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		report := &schema.Report{
			SchemaVersion:   schema.SchemaVersion,
			DevDiagVersion:  version.Version,
			RunID:           generateRunID(),
			RedactionStatus: string(redactEngine.Level),
			Repo:            schema.RepoInfo{Root: ""},
			Host:            schema.HostInfo{OS: ""},
			Collectors:      []schema.CollectorResult{},
			Findings:        []schema.Finding{},
		}

		if flagRedact == "off" {
			logger.Warn("redact", "redaction is disabled; secrets may be visible")
		}

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	doctorCmd.AddCommand(doctorSelfCmd)
	rootCmd.AddCommand(doctorCmd)
}
