package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	composecollector "github.com/meedoomostafa/devdiag/internal/collectors/compose"
	composestatuscollector "github.com/meedoomostafa/devdiag/internal/collectors/composestatus"
	diskcollector "github.com/meedoomostafa/devdiag/internal/collectors/disk"
	dockercollector "github.com/meedoomostafa/devdiag/internal/collectors/docker"
	envcollector "github.com/meedoomostafa/devdiag/internal/collectors/env"
	gitcollector "github.com/meedoomostafa/devdiag/internal/collectors/git"
	hostcollector "github.com/meedoomostafa/devdiag/internal/collectors/host"
	hostruncollector "github.com/meedoomostafa/devdiag/internal/collectors/hostruntime"
	networkcollector "github.com/meedoomostafa/devdiag/internal/collectors/network"
	permissioncollector "github.com/meedoomostafa/devdiag/internal/collectors/permission"
	podmancollector "github.com/meedoomostafa/devdiag/internal/collectors/podman"
	portcollector "github.com/meedoomostafa/devdiag/internal/collectors/port"
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

		collectorResults := runner.Run(ctx, allCollectors)

		// Build snapshot
		snapshotBuilder := graph.NewSnapshotBuilder()
		snapshot := snapshotBuilder.Build(collectorResults)

		// Evaluate policies
		engine := rules.NewM1Engine()
		rawFindings, err := engine.Evaluate(snapshot)
		if err != nil {
			logger.Error("policy", err.Error())
			return fmt.Errorf("policy evaluation failed: %w", err)
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
			Host:            schema.HostInfo{OS: ""},
			Collectors:      collectorResults,
			Findings:        sortedFindings,
		}

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return err
		}

		// Determine exit code based on findings severity
		maxSeverity := schema.SeverityInfo
		for _, f := range sortedFindings {
			if severityHigher(f.Severity, maxSeverity) {
				maxSeverity = f.Severity
			}
		}
		if maxSeverity == schema.SeverityHigh || maxSeverity == schema.SeverityCritical {
			return exitCodeError{code: exitcode.FindingsExist}
		}
		return nil
	},
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
	rootCmd.AddCommand(scanCmd)
}
