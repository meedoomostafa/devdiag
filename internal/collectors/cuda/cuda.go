package cuda

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var nvccVersionRegex = regexp.MustCompile(`release\s+(\d+\.\d+)`)

// CUDAInfo is the typed internal representation of CUDA runtime state.
type CUDAInfo struct {
	Version string // e.g. "12.1"
}

// Collector detects the CUDA toolkit version via nvcc.
type Collector struct {
	Runner cmdrunner.CommandRunner
}

func (c *Collector) Name() string {
	return "cuda"
}

// Collect runs nvcc --version and returns CUDA version evidence.
func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	if c.Runner == nil {
		c.Runner = cmdrunner.NewRealRunner()
	}

	info := &CUDAInfo{}
	evidence := []schema.Evidence{}
	notes := []string{}
	status := schema.CollectorOK

	cmdCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	res := c.Runner.Run(cmdCtx, "nvcc", "--version")
	cancel()

	if res.TimedOut {
		status = schema.CollectorTimeout
		notes = append(notes, "nvcc --version timed out")
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   status,
			Evidence: evidence,
			Notes:    notes,
		}, nil
	}

	if res.NotFound {
		applicable := false
		notes = append(notes, "nvcc not found")
		return schema.CollectorResult{
			Name:       c.Name(),
			Status:     schema.CollectorOK,
			Applicable: &applicable,
			Evidence:   evidence,
			Notes:      notes,
		}, nil
	}

	if res.ExitCode == 0 {
		ver, err := parseNVCCOutput(res.Stdout)
		if err == nil && ver != "" {
			info.Version = ver
		} else {
			notes = append(notes, "nvcc output parsing failed")
		}
	} else {
		notes = append(notes, "nvcc exited with error")
	}

	if info.Version != "" {
		evidence = append(evidence, schema.Evidence{Source: "cuda_runtime_version", Value: info.Version})
	}

	applicable := info.Version != ""
	return schema.CollectorResult{
		Name:       c.Name(),
		Status:     status,
		Applicable: &applicable,
		Evidence:   evidence,
		Notes:      notes,
	}, nil
}

// parseNVCCOutput extracts the release version from nvcc --version stdout.
// Expected format: "Cuda compilation tools, release 12.1, V12.1.105"
func parseNVCCOutput(stdout string) (string, error) {
	matches := nvccVersionRegex.FindStringSubmatch(stdout)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1]), nil
	}
	return "", nil
}
