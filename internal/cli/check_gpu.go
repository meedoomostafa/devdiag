package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	cudacollector "github.com/meedoomostafa/devdiag/internal/collectors/cuda"
	gpucollector "github.com/meedoomostafa/devdiag/internal/collectors/gpu"
	gpudockercollector "github.com/meedoomostafa/devdiag/internal/collectors/gpudocker"
	pythonmlcollector "github.com/meedoomostafa/devdiag/internal/collectors/pythonml"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/findings"
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/rules"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var flagCheckGPUPython bool
var flagGPUVerify bool
var flagAllowPull bool
var flagGPUVerifyImage string

var checkGPUCmd = &cobra.Command{
	Use:   "gpu",
	Short: "Check GPU/CUDA diagnostics and optionally Python ML frameworks",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		logger.Info("check", "running gpu diagnostic")

		ctx := cmd.Context()
		runner := collectors.NewRunner()

		allCollectors := []collectors.Collector{
			&gpucollector.Collector{},
			&cudacollector.Collector{},
		}
		if flagCheckGPUPython {
			allCollectors = append(allCollectors, &pythonmlcollector.Collector{})
		}
		allCollectors = append(allCollectors, &gpudockercollector.Collector{
			GPUVerify:      flagGPUVerify,
			AllowPull:      flagAllowPull,
			GPUVerifyImage: flagGPUVerifyImage,
		})

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
			Host:            populateHostInfo(collectorResults),
			Collectors:      collectorResults,
			Findings:        sortedFindings,
		}

		renderer := pickRenderer(colorMode)
		redacted := redactEngine.RedactReport(report)
		if err := renderer.Render(redacted, cmd.OutOrStdout()); err != nil {
			return err
		}

		code := exitCodeFromResults(sortedFindings, collectorResults, false)
		if code != exitcode.Success {
			return exitCodeError{code: code}
		}
		return nil
	},
}

func init() {
	checkGPUCmd.Flags().BoolVar(&flagCheckGPUPython, "python", false, "Include Python ML framework checks")
	checkGPUCmd.Flags().BoolVar(&flagGPUVerify, "gpu-verify", false, "Run Docker GPU container verification")
	checkGPUCmd.Flags().BoolVar(&flagAllowPull, "allow-pull", false, "Allow pulling GPU verification image if not present locally")
	checkGPUCmd.Flags().StringVar(&flagGPUVerifyImage, "gpu-verify-image", "", "Custom Docker image for GPU verification (default: nvidia/cuda:12.2.0-base-ubuntu22.04)")
	checkCmd.AddCommand(checkGPUCmd)
}
