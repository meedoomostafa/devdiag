package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	composecollector "github.com/meedoomostafa/devdiag/internal/collectors/compose"
	diskcollector "github.com/meedoomostafa/devdiag/internal/collectors/disk"
	envcollector "github.com/meedoomostafa/devdiag/internal/collectors/env"
	gitcollector "github.com/meedoomostafa/devdiag/internal/collectors/git"
	hostcollector "github.com/meedoomostafa/devdiag/internal/collectors/host"
	hostruncollector "github.com/meedoomostafa/devdiag/internal/collectors/hostruntime"
	networkcollector "github.com/meedoomostafa/devdiag/internal/collectors/network"
	permissioncollector "github.com/meedoomostafa/devdiag/internal/collectors/permission"
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

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run specific diagnostic checks",
}

func makeCheckRun(collectorsList func(string) []collectors.Collector) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
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

		logger.Info("check", fmt.Sprintf("checking path=%s", absPath))

		runner := collectors.NewRunner()
		ctx := cmd.Context()
		collectorResults := runner.Run(ctx, collectorsList(absPath))

		snapshotBuilder := graph.NewSnapshotBuilder()
		snapshot := snapshotBuilder.Build(collectorResults)

		engine := rules.NewM1Engine()
		rawFindings, err := engine.Evaluate(snapshot)
		if err != nil {
			logger.Error("policy", err.Error())
			return fmt.Errorf("policy evaluation failed: %w", err)
		}

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
	}
}

var checkEnvCmd = &cobra.Command{
	Use:   "env [path]",
	Short: "Check environment configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&envcollector.Collector{Root: path},
			&composecollector.Collector{Root: path},
		}
	}),
}

var checkRuntimesCmd = &cobra.Command{
	Use:   "runtimes [path]",
	Short: "Check runtime declarations and host installations",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&runtimecollector.Collector{Root: path},
			&hostruncollector.Collector{},
		}
	}),
}

var checkGitCmd = &cobra.Command{
	Use:   "git [path]",
	Short: "Check Git state",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&gitcollector.Collector{Root: path},
		}
	}),
}

var checkPortsCmd = &cobra.Command{
	Use:   "ports [path]",
	Short: "Check port conflicts with compose declarations",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&composecollector.Collector{Root: path},
			&portcollector.Collector{},
		}
	}),
}

var checkServicesCmd = &cobra.Command{
	Use:   "services [path]",
	Short: "Check systemd and network services",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&systemdcollector.Collector{RepoExpectsDocker: repocollector.HasDockerSignal(path)},
			&networkcollector.Collector{},
		}
	}),
}

var checkNetworkCmd = &cobra.Command{
	Use:   "network [path]",
	Short: "Check network and host metadata",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&networkcollector.Collector{},
			&hostcollector.Collector{},
		}
	}),
}

var checkFilesystemCmd = &cobra.Command{
	Use:   "filesystem [path]",
	Short: "Check filesystem permissions and disk usage",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func(path string) []collectors.Collector {
		return []collectors.Collector{
			&diskcollector.Collector{Path: path},
			&permissioncollector.Collector{Root: path},
		}
	}),
}

func init() {
	checkCmd.AddCommand(checkEnvCmd)
	checkCmd.AddCommand(checkRuntimesCmd)
	checkCmd.AddCommand(checkGitCmd)
	checkCmd.AddCommand(checkPortsCmd)
	checkCmd.AddCommand(checkServicesCmd)
	checkCmd.AddCommand(checkNetworkCmd)
	checkCmd.AddCommand(checkFilesystemCmd)
	rootCmd.AddCommand(checkCmd)
}
