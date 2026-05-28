package cli

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
	"context"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/findings"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/trace"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var runTraceEBPF = trace.RunEBPF

var (
	flagTraceScope     string
	flagTraceTimeout   time.Duration
	flagTraceMaxEvents int
	flagTraceBackend   string
)

var traceCmd = &cobra.Command{
	Use:   "trace [flags] -- <command> [args...]",
	Short: "Run a command under syscall tracing and diagnose failures",
	Long: `Runs the specified command under syscall tracing with configurable syscall scopes,
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

		scopes, err := trace.ParseScopes(flagTraceScope)
		if err != nil {
			logger.Warn("trace", err.Error())
			return exitCodeError{code: exitcode.InvalidInput}
		}
		backend, err := trace.ParseBackend(flagTraceBackend)
		if err != nil {
			logger.Warn("trace", err.Error())
			return exitCodeError{code: exitcode.InvalidInput}
		}

		command := args[0]
		commandArgs := args[1:]

		var res *trace.Result
		// Check strace availability after validating user input so malformed
		// flags return the stable invalid-input exit code on every host.
		if backend == trace.BackendStrace {
			if _, err := exec.LookPath("strace"); err != nil {
				logger.Warn("trace", "strace not found; trace mode unavailable")
				res = &trace.Result{
					Command:           command,
					Args:              commandArgs,
					Scopes:            scopes,
					Backend:           string(trace.BackendStrace),
					Events:            []trace.Event{},
					TraceUnavailable:  true,
					UnavailableReason: "strace_not_found",
					ExitCode:          -1,
					Notes:             []string{"trace unavailable: strace not found"},
				}
			}
		}

		if res == nil {
			logger.Info("trace", fmt.Sprintf("tracing command=%s backend=%s scopes=%v timeout=%s", command, backend, scopes, flagTraceTimeout))
			if backend == trace.BackendEBPF {
				tctx, cancel := context.WithTimeout(cmd.Context(), flagTraceTimeout)
				defer cancel()
				res, err = runTraceEBPF(tctx, scopes, command, commandArgs...)
			} else {
				runner := &trace.Runner{Timeout: flagTraceTimeout, MaxEvents: flagTraceMaxEvents}
				res, err = runner.Run(cmd.Context(), scopes, command, commandArgs...)
			}
		}
		if err != nil {
			logger.Error("trace", err.Error())
			return exitCodeError{code: exitcode.InternalError}
		}
		if res.TraceUnavailable && res.Backend == string(trace.BackendEBPF) {
			logger.Warn("trace", fmt.Sprintf("ebpf backend unavailable: %s", res.UnavailableReason))
		}

		// Analyze raw trace events first, then redact report/capsule output.
		// Raw events must never be printed or persisted unredacted.
		traceFindings := trace.Analyze(res.Events)

		// Build collector result
		collectorResult := schema.CollectorResult{
			Name:   "trace",
			Status: schema.CollectorOK,
			Evidence: []schema.Evidence{
				{Source: "trace_backend", Value: res.Backend},
				{Source: "trace_command", Value: command},
				{Source: "trace_scopes", Value: flagTraceScope},
				{Source: "trace_event_count", Value: fmt.Sprintf("%d", len(res.Events))},
			},
			Notes: res.Notes,
		}
		if res.SeccompRequested {
			collectorResult.Evidence = append(collectorResult.Evidence, schema.Evidence{Source: "seccomp_requested", Value: "true"})
		}
		if res.SeccompApplied {
			collectorResult.Evidence = append(collectorResult.Evidence, schema.Evidence{Source: "seccomp_applied", Value: "true"})
		}
		if res.SeccompDegraded {
			collectorResult.Evidence = append(collectorResult.Evidence, schema.Evidence{Source: "seccomp_degraded", Value: "true"})
		}
		if res.UnavailableReason != "" {
			collectorResult.Evidence = append(collectorResult.Evidence, schema.Evidence{Source: "trace_unavailable_reason", Value: res.UnavailableReason})
		}
		for _, ev := range res.CapabilityEvidence {
			collectorResult.Evidence = append(collectorResult.Evidence, schema.Evidence{Source: ev.Source, Value: ev.Value})
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
		if err := persistReport(".", redacted); err != nil {
			logger.Warn("trace", fmt.Sprintf("failed to persist report: %v", err))
		}

		// Persist redacted trace result artifact for capsule integration.
		if err := persistTraceResult(".", redacted.RunID, redactedResult); err != nil {
			logger.Warn("trace", fmt.Sprintf("failed to persist trace result: %v", err))
		}

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

func init() {
	traceCmd.Flags().StringVar(&flagTraceScope, "scope", "file", "Trace scopes: file, process, network (comma-separated)")
	traceCmd.Flags().DurationVar(&flagTraceTimeout, "timeout", 30*time.Second, "Maximum trace duration")
	traceCmd.Flags().IntVar(&flagTraceMaxEvents, "max-events", 10000, "Maximum trace events to parse")
	traceCmd.Flags().StringVar(&flagTraceBackend, "backend", "strace", "Trace backend: strace or ebpf")
	rootCmd.AddCommand(traceCmd)
}

func persistTraceResult(base, runID string, res *trace.Result) error {
	if base == "" {
		base = "."
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trace result: %w", err)
	}
	dir := artifact.RunDir(base, runID)
	if err := artifact.MkdirPrivate(dir); err != nil {
		return fmt.Errorf("create trace dir: %w", err)
	}
	path := filepath.Join(dir, "trace-result.json")
	if err := artifact.WriteFilePrivate(path, data); err != nil {
		return fmt.Errorf("write trace result: %w", err)
	}

	// Also update the 'latest' convenience files.
	// We want to mirror .devdiag/runs/LATEST -> .devdiag/latest
	latestDir := filepath.Join(base, ".devdiag", "latest")
	if err := artifact.MkdirPrivate(latestDir); err != nil {
		return fmt.Errorf("create latest trace dir: %w", err)
	}
	if err := artifact.WriteFilePrivate(filepath.Join(latestDir, "trace-result.json"), data); err != nil {
		return fmt.Errorf("write latest trace result: %w", err)
	}
	return nil
}
