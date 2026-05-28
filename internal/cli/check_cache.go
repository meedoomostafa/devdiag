package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	cachecollector "github.com/meedoomostafa/devdiag/internal/collectors/cache"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/findings"
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/rules"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var checkCacheCmd = &cobra.Command{
	Use:   "cache [path]",
	Short: "Check package and build cache ownership and size",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		absPath, err := filepath.Abs(scanPath)
		if err != nil {
			absPath = scanPath
		}

		logger.Info("check", fmt.Sprintf("checking cache path=%s", absPath))

		ctx := cmd.Context()
		runner := collectors.NewRunner()

		allCollectors := []collectors.Collector{
			&cachecollector.Collector{RepoRoot: absPath},
		}

		collectorResults := runner.Run(ctx, allCollectors)

		snapshotBuilder := graph.NewSnapshotBuilder()
		snapshot := snapshotBuilder.Build(collectorResults)

		engine := rules.NewM6Engine()
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
			Host:            populateHostInfo(collectorResults),
			Collectors:      collectorResults,
			Findings:        sortedFindings,
		}

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return err
		}

		code := exitCodeFromResultsForCommand(cmd, sortedFindings, collectorResults, false)
		if code != exitcode.Success {
			return exitCodeError{code: code}
		}
		return nil
	},
}

func init() {
	checkCmd.AddCommand(checkCacheCmd)
}
