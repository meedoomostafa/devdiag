package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/findings"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/trace"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var (
	flagTraceScope     string
	flagTraceTimeout   time.Duration
	flagTraceMaxEvents int
)

var traceCmd = &cobra.Command{
	Use:   "trace [flags] -- <command> [args...]",
	Short: "Run a command under strace and diagnose syscall failures",
	Long: `Runs the specified command under strace with configurable syscall scopes,
then analyzes the trace output to produce diagnostic findings.`,
	Example: `  devdiag trace --scope file -- npm run dev
  devdiag trace --scope file,process,network --timeout 60s -- python app.py`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if len(args) == 0 {
			logger.Warn("trace", "no command to trace; use '-- <command> [args...]'")
			return exitCodeError{code: exitcode.InvalidInput}
		}

		// Check strace availability
		if _, err := exec.LookPath("strace"); err != nil {
			logger.Warn("trace", "strace not found; trace mode unavailable")
			return exitCodeError{code: exitcode.TraceUnavailable}
		}

		scopes, err := trace.ParseScopes(flagTraceScope)
		if err != nil {
			logger.Warn("trace", err.Error())
			return exitCodeError{code: exitcode.InvalidInput}
		}

		command := args[0]
		commandArgs := args[1:]

		logger.Info("trace", fmt.Sprintf("tracing command=%s scopes=%v timeout=%s", command, scopes, flagTraceTimeout))

		runner := &trace.Runner{Timeout: flagTraceTimeout, MaxEvents: flagTraceMaxEvents}
		res, err := runner.Run(cmd.Context(), scopes, command, commandArgs...)
		if err != nil {
			logger.Error("trace", err.Error())
			return exitCodeError{code: exitcode.InternalError}
		}

		// Analyze raw trace events first, then redact report/capsule output.
		// Raw events must never be printed or persisted unredacted.
		traceFindings := trace.Analyze(res.Events)

		// Build collector result
		collectorResult := schema.CollectorResult{
			Name:   "trace",
			Status: schema.CollectorOK,
			Evidence: []schema.Evidence{
				{Source: "trace_command", Value: command},
				{Source: "trace_scopes", Value: flagTraceScope},
				{Source: "trace_event_count", Value: fmt.Sprintf("%d", len(res.Events))},
			},
			Notes: res.Notes,
		}
		if res.TimedOut {
			collectorResult.Status = schema.CollectorTimeout
			collectorResult.Partial = true
		}
		if res.Partial {
			collectorResult.Partial = true
		}
		if res.TraceUnavailable {
			collectorResult.Status = schema.CollectorUnavailable
		}

		// No M7Engine — trace findings come directly from analyzer
		var sortedFindings []schema.Finding
		if len(traceFindings) > 0 {
			aggregator := findings.NewAggregator()
			sortedFindings = aggregator.Add(traceFindings)
		}

		report := &schema.Report{
			SchemaVersion:   schema.SchemaVersion,
			DevDiagVersion:  version.Version,
			RunID:           generateRunID(),
			RedactionStatus: string(redactEngine.Level),
			Repo:            schema.RepoInfo{},
			Host:            schema.HostInfo{},
			Collectors:      []schema.CollectorResult{collectorResult},
			Findings:        sortedFindings,
		}

		// Redact the full trace result for capsule/report persistence
		redactedResult := trace.RedactResult(res, redactEngine)

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return exitCodeError{code: exitcode.InternalError}
		}

		// Persist redacted report
		if err := persistReport(redacted); err != nil {
			logger.Warn("trace", fmt.Sprintf("failed to persist report: %v", err))
		}

		// Persist redacted trace result artifact for capsule integration.
		// persistTraceResult writes to `.devdiag/latest/trace-result.json`.
		// The capsule builder reads this file and includes it as `snapshot/trace.json`.
		// Use the same base directory as persistReport ("." for trace command).
		if err := persistTraceResult(".", redactedResult); err != nil {
			logger.Warn("trace", fmt.Sprintf("failed to persist trace result: %v", err))
		}

		// Exit code precedence:
		// 1. Invalid input already handled above (2)
		// 2. Strace unavailable / ptrace denied → 7
		// 3. Traced command failure, timeout, signal death, or cancellation → 6 (ReproFailed)
		// 4. Findings exist → 1
		// 5. Partial trace due to limits → 3 (CollectorPartial)
		// 6. Internal error → 8
		if res.TraceUnavailable {
			return exitCodeError{code: exitcode.TraceUnavailable}
		}
		if res.ProcessFailed || res.Canceled || res.TimedOut || (res.ExitCode != 0 && res.ExitCode != -1) {
			return exitCodeError{code: exitcode.ReproFailed}
		}
		code := exitCodeFromResults(sortedFindings, report.Collectors, false)
		if code == exitcode.Success && res.Partial {
			return exitCodeError{code: exitcode.CollectorPartial}
		}
		if code != exitcode.Success {
			return exitCodeError{code: code}
		}
		return nil
	},
}

// persistTraceResult writes the redacted trace result to .devdiag/latest/trace-result.json
// for capsule integration. Uses 0700 dir and 0600 file permissions.
// Uses the same base directory resolution as persistReport (repo root or current directory).
func persistTraceResult(base string, res *trace.Result) error {
	if base == "" {
		base = "."
	}
	dir := filepath.Join(base, ".devdiag", "latest")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create trace dir: %w", err)
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trace result: %w", err)
	}
	path := filepath.Join(dir, "trace-result.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write trace result: %w", err)
	}
	return nil
}

func init() {
	traceCmd.Flags().StringVar(&flagTraceScope, "scope", "file", "Trace scopes: file, process, network (comma-separated)")
	traceCmd.Flags().DurationVar(&flagTraceTimeout, "timeout", 30*time.Second, "Maximum trace duration")
	traceCmd.Flags().IntVar(&flagTraceMaxEvents, "max-events", 10000, "Maximum trace events to parse")
	rootCmd.AddCommand(traceCmd)
}
