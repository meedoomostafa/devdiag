package cuda

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	nvccVersionRegex          = regexp.MustCompile(`release\s+(\d+\.\d+)`)
	nvidiaSMICUDAVersionRegex = regexp.MustCompile(`CUDA Version:\s+(\d+\.\d+)`)
)

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
		if driverCUDA, note := c.driverSupportedCUDAVersion(ctx); driverCUDA != "" {
			evidence = append(evidence, schema.Evidence{Source: "cuda_driver_supported_version", Value: driverCUDA})
			evidence = append(evidence, schema.Evidence{Source: "cuda_compatibility", Value: cudaCompatibility(info.Version, driverCUDA)})
		} else if note != "" {
			notes = append(notes, note)
		}
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

func (c *Collector) driverSupportedCUDAVersion(ctx context.Context) (string, string) {
	cmdCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	res := c.Runner.Run(cmdCtx, "nvidia-smi")
	cancel()
	if res.TimedOut {
		return "", "nvidia-smi CUDA compatibility probe timed out"
	}
	if res.ExitCode != 0 || res.NotFound {
		return "", ""
	}
	version := parseNvidiaSMICUDAVersion(res.Stdout)
	if version == "" {
		return "", "nvidia-smi CUDA compatibility output parsing failed"
	}
	return version, ""
}

func parseNvidiaSMICUDAVersion(stdout string) string {
	matches := nvidiaSMICUDAVersionRegex.FindStringSubmatch(stdout)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func cudaCompatibility(runtimeVersion, driverSupportedVersion string) string {
	cmp, ok := compareCUDAVersions(runtimeVersion, driverSupportedVersion)
	if !ok {
		return "unknown"
	}
	if cmp > 0 {
		return "runtime_newer_than_driver"
	}
	return "compatible"
}

func compareCUDAVersions(a, b string) (int, bool) {
	amajor, aminor, ok := parseMajorMinor(a)
	if !ok {
		return 0, false
	}
	bmajor, bminor, ok := parseMajorMinor(b)
	if !ok {
		return 0, false
	}
	if amajor != bmajor {
		if amajor > bmajor {
			return 1, true
		}
		return -1, true
	}
	if aminor != bminor {
		if aminor > bminor {
			return 1, true
		}
		return -1, true
	}
	return 0, true
}

func parseMajorMinor(version string) (int, int, bool) {
	parts := strings.SplitN(strings.TrimSpace(version), ".", 3)
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor := 0
	if len(parts) > 1 && parts[1] != "" {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, false
		}
	}
	return major, minor, true
}
