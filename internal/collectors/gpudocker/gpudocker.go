package gpudocker

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// DockerGPUInfo is the typed internal representation of container GPU state.
type DockerGPUInfo struct {
	ToolkitVersion          string
	ContainerCLIVersion     string
	ContainerRuntimeVersion string
	DockerGPURuntime        string // e.g. "nvidia" or ""
	DaemonGPURuntime        bool
	VerifyResult            string // success/failed/timeout/image_missing/skipped
	VerifyStdout            string
}

// Collector detects NVIDIA Container Toolkit and Docker GPU runtime config.
type Collector struct {
	Runner         cmdrunner.CommandRunner
	GPUVerify      bool
	GPUVerifyImage string
	AllowPull      bool
}

const defaultVerifyImage = "nvidia/cuda:12.2.0-base-ubuntu22.04"

func (c *Collector) Name() string {
	return "gpudocker"
}

// Collect runs multi-signal container GPU detection.
func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	if c.Runner == nil {
		c.Runner = cmdrunner.NewRealRunner()
	}
	if c.GPUVerifyImage == "" {
		c.GPUVerifyImage = defaultVerifyImage
	}

	info := &DockerGPUInfo{}
	evidence := []schema.Evidence{}
	notes := []string{}
	status := schema.CollectorOK
	partial := false

	// Signal 1: nvidia-ctk --version
	cmdCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	res := c.Runner.Run(cmdCtx, "nvidia-ctk", "--version")
	cancel()
	if res.ExitCode == 0 && res.Stdout != "" {
		info.ToolkitVersion = firstLine(res.Stdout)
		evidence = append(evidence, schema.Evidence{Source: "nvidia_container_toolkit_version", Value: info.ToolkitVersion})
	}

	// Signal 2: nvidia-container-cli --version
	cmdCtx, cancel = context.WithTimeout(ctx, 1*time.Second)
	res = c.Runner.Run(cmdCtx, "nvidia-container-cli", "--version")
	cancel()
	if res.ExitCode == 0 && res.Stdout != "" {
		info.ContainerCLIVersion = firstLine(res.Stdout)
		evidence = append(evidence, schema.Evidence{Source: "nvidia_container_cli_version", Value: info.ContainerCLIVersion})
	}

	// Signal 3: nvidia-container-runtime --version
	cmdCtx, cancel = context.WithTimeout(ctx, 1*time.Second)
	res = c.Runner.Run(cmdCtx, "nvidia-container-runtime", "--version")
	cancel()
	if res.ExitCode == 0 && res.Stdout != "" {
		info.ContainerRuntimeVersion = firstLine(res.Stdout)
		evidence = append(evidence, schema.Evidence{Source: "nvidia_container_runtime_version", Value: info.ContainerRuntimeVersion})
	}

	// Signal 4: docker info --format '{{json .}}'
	cmdCtx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	res = c.Runner.Run(cmdCtx, "docker", "info", "--format", "{{json .}}")
	cancel()

	if res.NotFound {
		// Docker binary not installed
		evidence = append(evidence, schema.Evidence{Source: "docker_binary_present", Value: "false"})
	} else {
		// Docker binary is present
		evidence = append(evidence, schema.Evidence{Source: "docker_binary_present", Value: "true"})
		if res.ExitCode == 0 {
			// Docker daemon is accessible
			evidence = append(evidence, schema.Evidence{Source: "docker_daemon_accessible", Value: "true"})
			evidence = append(evidence, schema.Evidence{Source: "docker_installed", Value: "true"})
			runtimeName := extractDockerGPURuntime(res.Stdout)
			if runtimeName != "" {
				info.DockerGPURuntime = runtimeName
				info.DaemonGPURuntime = true
				evidence = append(evidence, schema.Evidence{Source: "docker_gpu_runtime_present", Value: "true"})
				evidence = append(evidence, schema.Evidence{Source: "docker_gpu_runtime_name", Value: runtimeName})
			}
		} else {
			// Docker binary exists but daemon is not accessible
			evidence = append(evidence, schema.Evidence{Source: "docker_daemon_accessible", Value: "false"})
			// Signal 5: fallback to /etc/docker/daemon.json
			runtimeName := extractDaemonJSONRuntime("/etc/docker/daemon.json")
			if runtimeName != "" {
				info.DockerGPURuntime = runtimeName
				info.DaemonGPURuntime = true
				evidence = append(evidence, schema.Evidence{Source: "docker_gpu_runtime_present", Value: "true"})
				evidence = append(evidence, schema.Evidence{Source: "docker_gpu_runtime_name", Value: runtimeName})
			}
		}
	}

	if !info.DaemonGPURuntime {
		evidence = append(evidence, schema.Evidence{Source: "docker_gpu_runtime_present", Value: "false"})
	}

	// Signal 6: opt-in GPU verification
	if c.GPUVerify {
		result, stdout := c.runGPUVerification(ctx)
		info.VerifyResult = result
		info.VerifyStdout = stdout
		evidence = append(evidence, schema.Evidence{Source: "docker_gpu_verify_result", Value: info.VerifyResult})
		if info.VerifyStdout != "" {
			evidence = append(evidence, schema.Evidence{Source: "docker_gpu_verify_stdout", Value: info.VerifyStdout})
		}
	}

	applicable := info.ToolkitVersion != "" || info.ContainerCLIVersion != "" ||
		info.ContainerRuntimeVersion != "" || info.DaemonGPURuntime || c.GPUVerify

	if !applicable {
		notes = append(notes, "NVIDIA Container Toolkit not detected")
	}

	return schema.CollectorResult{
		Name:       c.Name(),
		Status:     status,
		Applicable: &applicable,
		Partial:    partial,
		Evidence:   evidence,
		Notes:      notes,
	}, nil
}

func (c *Collector) runGPUVerification(ctx context.Context) (string, string) {
	// Check if image exists locally using docker image inspect
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	res := c.Runner.Run(cmdCtx, "docker", "image", "inspect", c.GPUVerifyImage)
	cancel()

	if res.ExitCode != 0 {
		if !c.AllowPull {
			return "image_missing", ""
		}
	}

	// Run verification container
	cmdCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	res = c.Runner.Run(cmdCtx, "docker", "run", "--rm", "--gpus", "all", c.GPUVerifyImage, "nvidia-smi")
	cancel()

	if res.TimedOut {
		return "timeout", res.Stdout
	}
	if res.ExitCode == 0 {
		return "success", res.Stdout
	}
	return "failed", res.Stdout
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// extractDockerGPURuntime parses docker info JSON for nvidia runtime.
func extractDockerGPURuntime(stdout string) string {
	var info struct {
		Runtimes       map[string]interface{} `json:"Runtimes"`
		DefaultRuntime string                 `json:"DefaultRuntime"`
	}
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return ""
	}
	if info.DefaultRuntime == "nvidia" || info.DefaultRuntime == "nvidia-container-runtime" {
		return info.DefaultRuntime
	}
	if _, ok := info.Runtimes["nvidia"]; ok {
		return "nvidia"
	}
	// Some versions nest under lower-case key
	if _, ok := info.Runtimes["nvidia-container-runtime"]; ok {
		return "nvidia-container-runtime"
	}
	return ""
}

// extractDaemonJSONRuntime reads /etc/docker/daemon.json for runtime config.
func extractDaemonJSONRuntime(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var daemon struct {
		Runtimes map[string]interface{} `json:"runtimes"`
	}
	if err := json.Unmarshal(data, &daemon); err != nil {
		return ""
	}
	if _, ok := daemon.Runtimes["nvidia"]; ok {
		return "nvidia"
	}
	if _, ok := daemon.Runtimes["nvidia-container-runtime"]; ok {
		return "nvidia-container-runtime"
	}
	return ""
}
