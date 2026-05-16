package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/redact"
	"github.com/meedoomostafa/devdiag/internal/repro"
	"github.com/meedoomostafa/devdiag/internal/repro/classifier"
	"github.com/meedoomostafa/devdiag/internal/rules"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var reproTimeout time.Duration

var reproCmd = &cobra.Command{
	Use:   "repro -- <cmd> [args...]",
	Short: "Run a command and capture structured reproduction evidence",
	Args:  cobra.MinimumNArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if len(args) == 0 {
			logger.Error("repro", "no command provided after --")
			return exitCodeError{code: exitcode.InvalidInput}
		}

		command := args[0]
		cmdArgs := args[1:]

		logger.Info("repro", fmt.Sprintf("running command=%s args=%v timeout=%v", command, cmdArgs, reproTimeout))

		runner := repro.NewRunner()
		if reproTimeout > 0 {
			runner.Timeout = reproTimeout
		}

		result, startErr := runner.Run(cmd.Context(), command, cmdArgs)
		if startErr != nil {
			logger.Error("repro", fmt.Sprintf("command failed to start: %v", startErr))
			return exitCodeError{code: exitcode.ReproFailed}
		}

		// Classify output
		clf := classifier.New()
		result.Classifications = clf.Classify(result.StdoutPreview, result.StderrPreview)

		// Build repro collector result for rules engine
		reproCollector := schema.CollectorResult{
			Name:   "repro",
			Status: schema.CollectorOK,
			Evidence: []schema.Evidence{
				{Source: "repro_command", Value: command},
				{Source: "repro_args", Value: strings.Join(cmdArgs, " ")},
				{Source: "repro_exit_code", Value: fmt.Sprintf("%d", result.ExitCode)},
				{Source: "repro_duration_ms", Value: fmt.Sprintf("%d", result.DurationMs)},
				{Source: "repro_timed_out", Value: fmt.Sprintf("%v", result.TimedOut)},
			},
		}
		if result.TimedOut {
			reproCollector.Status = schema.CollectorTimeout
		}
		for _, c := range result.Classifications {
			reproCollector.Evidence = append(reproCollector.Evidence, schema.Evidence{
				Source: "repro_classification",
				Value:  c.Kind,
			})
		}

		// Run rules engine
		engine := rules.NewM1Engine()
		snapshot := graph.NormalizedSnapshot{Collectors: []schema.CollectorResult{reproCollector}}
		rawFindings, err := engine.Evaluate(snapshot)
		if err != nil {
			logger.Error("policy", err.Error())
			return fmt.Errorf("policy evaluation failed: %w", err)
		}

		// Build report
		runID := generateRunID()
		report := &schema.Report{
			SchemaVersion:   schema.SchemaVersion,
			DevDiagVersion:  version.Version,
			RunID:           runID,
			RedactionStatus: string(redactEngine.Level),
			Repo:            schema.RepoInfo{Root: result.WorkingDir},
			Host:            schema.HostInfo{OS: ""},
			Collectors:      []schema.CollectorResult{reproCollector},
			Findings:        rawFindings,
		}

		// Redact before persistence
		redactedReport := redactEngine.RedactReport(report)

		// Write run artifacts
		if err := writeReproArtifacts(runID, redactedReport, result, redactEngine); err != nil {
			logger.Warn("repro", fmt.Sprintf("artifact write failed: %v", err))
		}

		// Render
		renderer := pickRenderer(colorMode)
		if err := renderer.Render(redactedReport, cmd.OutOrStdout()); err != nil {
			return err
		}

		// Exit code contract
		maxSeverity := schema.SeverityInfo
		for _, f := range rawFindings {
			if severityHigher(f.Severity, maxSeverity) {
				maxSeverity = f.Severity
			}
		}
		if maxSeverity == schema.SeverityHigh || maxSeverity == schema.SeverityCritical || result.ExitCode != 0 {
			return exitCodeError{code: exitcode.FindingsExist}
		}
		return nil
	},
}

func writeReproArtifacts(runID string, report *schema.Report, result *repro.ReproResult, engine *redact.Engine) error {
	runsDir := filepath.Join(".devdiag", "runs", runID)
	if err := os.MkdirAll(filepath.Join(runsDir, "logs"), 0755); err != nil {
		return err
	}

	// Report
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runsDir, "report.json"), reportData, 0644); err != nil {
		return err
	}

	// Repro result — redact previews and excerpts before persistence
	redactedResult := *result
	redactedResult.StdoutPreview = engine.RedactString(result.StdoutPreview, "repro_stdout")
	redactedResult.StderrPreview = engine.RedactString(result.StderrPreview, "repro_stderr")
	for i := range redactedResult.Classifications {
		redactedResult.Classifications[i].Excerpt = engine.RedactString(redactedResult.Classifications[i].Excerpt, "repro_classification")
	}
	reproData, err := json.MarshalIndent(&redactedResult, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runsDir, "repro.json"), reproData, 0644); err != nil {
		return err
	}

	// Captured logs (already redacted previews)
	stdoutLog := engine.RedactString(result.StdoutPreview, "repro_stdout")
	stderrLog := engine.RedactString(result.StderrPreview, "repro_stderr")
	if err := os.WriteFile(filepath.Join(runsDir, "logs", "command.stdout.log"), []byte(stdoutLog), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runsDir, "logs", "command.stderr.log"), []byte(stderrLog), 0644); err != nil {
		return err
	}

	return nil
}

func init() {
	reproCmd.Flags().DurationVar(&reproTimeout, "timeout", 60*time.Second, "Max duration for the repro command")
	rootCmd.AddCommand(reproCmd)
}
