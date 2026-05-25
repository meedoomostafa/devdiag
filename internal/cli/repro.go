package cli

import (
	"encoding/json"
	"fmt"
	"io"
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
		runner.Redactor = redactEngine
		if reproTimeout > 0 {
			runner.Timeout = reproTimeout
		}

		runID := generateRunID()
		redactedArgsList := redactArgs(cmdArgs, redactEngine)
		redactedArgs := strings.Join(redactedArgsList, " ")
		ndjsonStarted := flagFormat == "ndjson"
		if ndjsonStarted {
			if err := renderReproNDJSONStart(cmd.OutOrStdout(), runID, command, redactedArgsList, redactEngine); err != nil {
				return err
			}
		}

		result, startErr := runner.Run(cmd.Context(), command, cmdArgs)

		// Classify output (even if start failed, we may have partial data)
		clf := classifier.New()
		result.Classifications = clf.Classify(result.StdoutPreview, result.StderrPreview)

		// Build repro collector result for rules engine
		reproCollector := schema.CollectorResult{
			Name:   "repro",
			Status: schema.CollectorOK,
			Evidence: []schema.Evidence{
				{Source: "repro_command", Value: command},
				{Source: "repro_args", Value: redactedArgs},
				{Source: "repro_exit_code", Value: fmt.Sprintf("%d", result.ExitCode)},
				{Source: "repro_duration_ms", Value: fmt.Sprintf("%d", result.DurationMs)},
				{Source: "repro_timed_out", Value: fmt.Sprintf("%v", result.TimedOut)},
			},
		}
		if result.TimedOut {
			reproCollector.Status = schema.CollectorTimeout
		}
		if startErr != nil {
			reproCollector.Status = schema.CollectorFailed
			reproCollector.Notes = append(reproCollector.Notes, startErr.Error())
			reproCollector.Partial = true
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
		if flagFormat == "ndjson" {
			redactedResult := redactReproResult(result, redactEngine)
			if err := renderReproNDJSON(cmd.OutOrStdout(), redactedReport.RunID, redactedResult, redactedReport.Findings, ndjsonStarted); err != nil {
				return err
			}
		} else {
			renderer := pickRenderer(colorMode)
			if err := renderer.Render(redactedReport, cmd.OutOrStdout()); err != nil {
				return err
			}
		}

		if startErr != nil {
			logger.Error("repro", fmt.Sprintf("command failed to start: %v", startErr))
		}

		reproFailed := startErr != nil || result.ExitCode != 0
		code := exitCodeFromResults(rawFindings, []schema.CollectorResult{reproCollector}, reproFailed)
		if code != exitcode.Success {
			return exitCodeError{code: code}
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
	if err := os.WriteFile(filepath.Join(runsDir, "report.json"), reportData, 0600); err != nil {
		return err
	}

	// Repro result — redact args, previews, classification excerpts, and timeline before persistence.
	redactedResult := redactReproResult(result, engine)
	reproData, err := json.MarshalIndent(redactedResult, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runsDir, "repro.json"), reproData, 0600); err != nil {
		return err
	}

	// Captured logs (already redacted previews)
	stdoutLog := engine.RedactString(result.StdoutPreview, "repro_stdout")
	stderrLog := engine.RedactString(result.StderrPreview, "repro_stderr")
	if err := os.WriteFile(filepath.Join(runsDir, "logs", "command.stdout.log"), []byte(stdoutLog), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runsDir, "logs", "command.stderr.log"), []byte(stderrLog), 0600); err != nil {
		return err
	}

	return nil
}

func redactArgs(args []string, engine *redact.Engine) []string {
	redacted := make([]string, len(args))
	for i, arg := range args {
		redacted[i] = engine.RedactString(arg, "repro_arg")
	}
	return redacted
}

func redactReproResult(result *repro.ReproResult, engine *redact.Engine) *repro.ReproResult {
	if result == nil {
		return nil
	}
	redacted := *result
	redacted.Args = redactArgs(result.Args, engine)
	redacted.WorkingDir = engine.RedactString(result.WorkingDir, "repro_working_dir")
	redacted.StdoutPreview = engine.RedactString(result.StdoutPreview, "repro_stdout")
	redacted.StderrPreview = engine.RedactString(result.StderrPreview, "repro_stderr")
	redacted.Classifications = make([]repro.Classification, len(result.Classifications))
	for i, classification := range result.Classifications {
		redacted.Classifications[i] = classification
		redacted.Classifications[i].Excerpt = engine.RedactString(classification.Excerpt, "repro_classification")
	}
	redacted.Timeline = make([]repro.ReproEvent, len(result.Timeline))
	for i, event := range result.Timeline {
		redacted.Timeline[i] = event
		redacted.Timeline[i].Detail = engine.RedactString(event.Detail, "repro_timeline")
	}
	return &redacted
}

type reproNDJSONRecord struct {
	Type       string          `json:"type"`
	RunID      string          `json:"run_id"`
	Timestamp  string          `json:"timestamp,omitempty"`
	Event      string          `json:"event,omitempty"`
	Detail     string          `json:"detail,omitempty"`
	Command    string          `json:"command,omitempty"`
	Args       []string        `json:"args,omitempty"`
	ExitCode   *int            `json:"exit_code,omitempty"`
	TimedOut   bool            `json:"timed_out,omitempty"`
	DurationMs int64           `json:"duration_ms,omitempty"`
	Finding    *schema.Finding `json:"finding,omitempty"`
}

func renderReproNDJSONStart(w io.Writer, runID, command string, redactedArgs []string, engine *redact.Engine) error {
	detail := strings.TrimSpace(command + " " + strings.Join(redactedArgs, " "))
	record := reproNDJSONRecord{
		Type:      "repro_start",
		RunID:     runID,
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Event:     "start",
		Detail:    engine.RedactString(detail, "repro_timeline"),
		Command:   engine.RedactString(command, "repro_command"),
		Args:      redactedArgs,
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(record); err != nil {
		return err
	}
	return flushWriter(w)
}

func renderReproNDJSON(w io.Writer, runID string, result *repro.ReproResult, findings []schema.Finding, skipStart bool) error {
	enc := json.NewEncoder(w)
	if result != nil {
		for _, event := range result.Timeline {
			if skipStart && event.Type == "start" {
				continue
			}
			record := reproNDJSONRecord{
				Type:      "repro_" + event.Type,
				RunID:     runID,
				Timestamp: event.Timestamp.Format(time.RFC3339Nano),
				Event:     event.Type,
				Detail:    event.Detail,
			}
			if event.Type == "start" {
				record.Command = result.Command
				record.Args = result.Args
			}
			if err := enc.Encode(record); err != nil {
				return err
			}
		}
		exitCode := result.ExitCode
		if err := enc.Encode(reproNDJSONRecord{
			Type:       "repro_result",
			RunID:      runID,
			ExitCode:   &exitCode,
			TimedOut:   result.TimedOut,
			DurationMs: result.DurationMs,
		}); err != nil {
			return err
		}
	}
	for i := range findings {
		finding := findings[i]
		if err := enc.Encode(reproNDJSONRecord{
			Type:    "finding",
			RunID:   runID,
			Finding: &finding,
		}); err != nil {
			return err
		}
	}
	return nil
}

func flushWriter(w io.Writer) error {
	if flusher, ok := w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	if flusher, ok := w.(interface{ Flush() }); ok {
		flusher.Flush()
	}
	return nil
}

func init() {
	reproCmd.Flags().DurationVar(&reproTimeout, "timeout", 60*time.Second, "Max duration for the repro command")
	rootCmd.AddCommand(reproCmd)
}
