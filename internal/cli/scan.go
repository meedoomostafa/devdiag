package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	"github.com/meedoomostafa/devdiag/internal/collectors/cache"
	cicollector "github.com/meedoomostafa/devdiag/internal/collectors/ci"
	composecollector "github.com/meedoomostafa/devdiag/internal/collectors/compose"
	composestatuscollector "github.com/meedoomostafa/devdiag/internal/collectors/composestatus"
	cudacollector "github.com/meedoomostafa/devdiag/internal/collectors/cuda"
	diskcollector "github.com/meedoomostafa/devdiag/internal/collectors/disk"
	dockercollector "github.com/meedoomostafa/devdiag/internal/collectors/docker"
	envcollector "github.com/meedoomostafa/devdiag/internal/collectors/env"
	gitcollector "github.com/meedoomostafa/devdiag/internal/collectors/git"
	gpucollector "github.com/meedoomostafa/devdiag/internal/collectors/gpu"
	gpudockercollector "github.com/meedoomostafa/devdiag/internal/collectors/gpudocker"
	hostcollector "github.com/meedoomostafa/devdiag/internal/collectors/host"
	hostruncollector "github.com/meedoomostafa/devdiag/internal/collectors/hostruntime"
	networkcollector "github.com/meedoomostafa/devdiag/internal/collectors/network"
	permissioncollector "github.com/meedoomostafa/devdiag/internal/collectors/permission"
	podmancollector "github.com/meedoomostafa/devdiag/internal/collectors/podman"
	portcollector "github.com/meedoomostafa/devdiag/internal/collectors/port"
	pythonmlcollector "github.com/meedoomostafa/devdiag/internal/collectors/pythonml"
	repocollector "github.com/meedoomostafa/devdiag/internal/collectors/repo"
	runtimecollector "github.com/meedoomostafa/devdiag/internal/collectors/runtime"
	systemdcollector "github.com/meedoomostafa/devdiag/internal/collectors/systemd"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/findings"
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/rules"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var scanSaveReport bool

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run a diagnostic scan on the given path",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if flagRedact == "off" {
			logger.Warn("redact", "redaction is disabled; secrets may be visible")
		}

		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		absPath, err := filepath.Abs(scanPath)
		if err != nil {
			absPath = scanPath
		}

		logger.Info("scan", fmt.Sprintf("scanning path=%s", absPath))

		// Run all M1 repo collectors + M2 host collectors + self collector
		runner := collectors.NewRunner()
		ctx := cmd.Context()

		// Pre-detect container signals for conditional M3 inclusion
		repoHasDocker := repocollector.HasDockerSignal(absPath)
		repoHasPodman := repocollector.HasPodmanSignal(absPath)
		repoHasContainers := repoHasDocker || repoHasPodman

		allCollectors := []collectors.Collector{
			&repocollector.Collector{Root: absPath},
			&envcollector.Collector{Root: absPath},
			&composecollector.Collector{Root: absPath},
			&gitcollector.Collector{Root: absPath},
			&runtimecollector.Collector{Root: absPath},
			&hostcollector.Collector{},
			&hostruncollector.Collector{},
			&diskcollector.Collector{Path: absPath},
			&portcollector.Collector{},
			&networkcollector.Collector{},
			&systemdcollector.Collector{RepoExpectsDocker: repoHasDocker},
			&permissioncollector.Collector{Root: absPath},
			&collectors.SelfCollector{},
		}

		// Conditionally include M3 container collectors
		if repoHasContainers {
			allCollectors = append(allCollectors,
				&dockercollector.Collector{},
				&podmancollector.Collector{},
				&composestatuscollector.Collector{Root: absPath},
			)
		}

		// Conditionally include CI collector when workflows exist
		if repocollector.HasCISignal(absPath) {
			allCollectors = append(allCollectors, &cicollector.Collector{Root: absPath})
		}

		// Conditionally include M6 collectors when --profile ai-ml is set
		if flagProfile == "ai-ml" {
			allCollectors = append(allCollectors,
				&gpucollector.Collector{},
				&cudacollector.Collector{},
			)
			// Python ML and cache only if repo signals exist, unless profile explicitly forces them
			repoHasPython := repocollector.HasPythonSignal(absPath)
			if repoHasPython || flagProfile == "ai-ml" {
				allCollectors = append(allCollectors, &pythonmlcollector.Collector{})
			}
			allCollectors = append(allCollectors,
				&gpudockercollector.Collector{},
				&cache.Collector{RepoRoot: absPath},
			)
		}

		collectorResults := runner.Run(ctx, allCollectors)

		// Build snapshot
		snapshotBuilder := graph.NewSnapshotBuilder()
		snapshot := snapshotBuilder.Build(collectorResults)

		// Evaluate M1 policies
		engine := rules.NewM1Engine()
		rawFindings, err := engine.Evaluate(snapshot)
		if err != nil {
			logger.Error("policy", err.Error())
			return fmt.Errorf("policy evaluation failed: %w", err)
		}

		// Evaluate M6 policies when profile is ai-ml
		if flagProfile == "ai-ml" {
			m6Engine := rules.NewM6Engine()
			m6Findings, err := m6Engine.Evaluate(snapshot)
			if err != nil {
				logger.Error("m6-policy", err.Error())
			} else {
				rawFindings = append(rawFindings, m6Findings...)
			}
		}

		// Evaluate M8 policies when CI workflows exist
		if repocollector.HasCISignal(absPath) {
			m8Engine := rules.NewM8Engine()
			m8Findings, err := m8Engine.Evaluate(snapshot)
			if err != nil {
				logger.Error("m8-policy", err.Error())
			} else {
				rawFindings = append(rawFindings, m8Findings...)
			}
		}

		// Aggregate findings for stable ordering
		aggregator := findings.NewAggregator()
		sortedFindings := aggregator.Add(rawFindings)

		report := &schema.Report{
			SchemaVersion:   schema.SchemaVersion,
			DevDiagVersion:  version.Version,
			RunID:           generateRunID(),
			RedactionStatus: string(redactEngine.Level),
			Repo:            schema.RepoInfo{Root: absPath},
			Host:            populateHostInfo(collectorResults),
			Collectors:      collectorResults,
			Findings:        sortedFindings,
		}

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return err
		}

		// Persist reports only when explicitly requested. By default scan is read-only.
		if scanSaveReport {
			if err := persistReport(report); err != nil {
				logger.Warn("scan", fmt.Sprintf("failed to persist report: %v", err))
			}
		}

		code := exitCodeFromResults(sortedFindings, collectorResults, false)
		if code != exitcode.Success {
			return exitCodeError{code: code}
		}
		return nil
	},
}

func persistReport(report *schema.Report) error {
	base := report.Repo.Root
	if base == "" {
		base = "."
	}
	runsDir := filepath.Join(base, ".devdiag", "runs", report.RunID)
	if err := os.MkdirAll(runsDir, 0755); err != nil {
		return fmt.Errorf("create runs dir: %w", err)
	}
	reportPath := filepath.Join(runsDir, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func severityHigher(a, b schema.Severity) bool {
	order := map[schema.Severity]int{
		schema.SeverityCritical: 4,
		schema.SeverityHigh:     3,
		schema.SeverityMedium:   2,
		schema.SeverityLow:      1,
		schema.SeverityInfo:     0,
	}
	return order[a] > order[b]
}

func init() {
	scanCmd.Flags().BoolVar(&scanSaveReport, "save-report", false, "Persist report under .devdiag/runs for fix and capsule commands")
	rootCmd.AddCommand(scanCmd)
}
