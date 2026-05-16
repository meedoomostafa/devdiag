package cli

import (
	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List available diagnostic rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available diagnostic rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if flagRedact == "off" {
			logger.Warn("redact", "redaction is disabled; secrets may be visible")
		}

		switch flagFormat {
		case "json", "ndjson", "markdown":
			report := &schema.Report{
				SchemaVersion:   schema.SchemaVersion,
				DevDiagVersion:  version.Version,
				RunID:           generateRunID(),
				RedactionStatus: string(redactEngine.Level),
				Repo:            schema.RepoInfo{},
				Host:            schema.HostInfo{},
				Collectors:      []schema.CollectorResult{},
				Findings: []schema.Finding{
					{
						ID:              "F-RULES-000",
						Title:           "Rule engine will be available in Milestone 1",
						Severity:        schema.SeverityInfo,
						Confidence:      1.0,
						Symptom:         "No rules are loaded in Milestone 0",
						RedactionStatus: "safe",
					},
				},
			}
			renderer := pickRenderer(colorMode)
			redacted := redactEngine.RedactReport(report)
			return renderer.Render(redacted, cmd.OutOrStdout())
		default:
			// human mode — route through renderer for consistency
			report := &schema.Report{
				SchemaVersion:   schema.SchemaVersion,
				DevDiagVersion:  version.Version,
				RunID:           generateRunID(),
				RedactionStatus: string(redactEngine.Level),
				Repo:            schema.RepoInfo{},
				Host:            schema.HostInfo{},
				Collectors:      []schema.CollectorResult{},
				Findings: []schema.Finding{
					{
						ID:              "F-RULES-000",
						Title:           "Rule engine will be available in Milestone 1",
						Severity:        schema.SeverityInfo,
						Confidence:      1.0,
						Symptom:         "No rules are loaded in Milestone 0",
						RedactionStatus: "safe",
					},
				},
			}
			renderer := pickRenderer(colorMode)
			redacted := redactEngine.RedactReport(report)
			return renderer.Render(redacted, cmd.OutOrStdout())
		}
	},
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
	rootCmd.AddCommand(rulesCmd)
}
