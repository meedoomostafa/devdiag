package pythonml

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// PyTorchInfo is the typed internal representation for PyTorch state.
type PyTorchInfo struct {
	Version       string
	CUDAAvailable bool
	CUDAVersion   string
	DeviceCount   int
	Devices       []string
}

// TensorFlowInfo is the typed internal representation for TensorFlow state.
type TensorFlowInfo struct {
	Version  string
	GPUCount int
}

// JAXInfo is the typed internal representation for JAX state.
type JAXInfo struct {
	Version  string
	GPUCount int
}

// MLInfo groups all discovered ML framework state.
type MLInfo struct {
	PyTorch    *PyTorchInfo
	TensorFlow *TensorFlowInfo
	JAX        *JAXInfo
	PythonPath string
}

// Collector detects Python ML frameworks and their GPU visibility.
type Collector struct {
	Runner       cmdrunner.CommandRunner
	pythonFinder func() string
}

func (c *Collector) Name() string {
	return "pythonml"
}

// Collect discovers Python ML frameworks and collects GPU-related evidence.
func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	if c.Runner == nil {
		c.Runner = cmdrunner.NewRealRunner()
	}
	if c.pythonFinder == nil {
		c.pythonFinder = defaultPythonFinder
	}

	info := &MLInfo{}
	evidence := []schema.Evidence{}
	notes := []string{}
	status := schema.CollectorOK
	partial := false

	pythonPath := c.pythonFinder()
	if pythonPath == "" {
		applicable := false
		notes = append(notes, "no Python interpreter found")
		return schema.CollectorResult{
			Name:       c.Name(),
			Status:     status,
			Applicable: &applicable,
			Evidence:   evidence,
			Notes:      notes,
		}, nil
	}
	info.PythonPath = pythonPath

	// Step 1: detect which packages are importable
	packages, err := c.detectPackages(ctx, pythonPath)
	if err != nil {
		notes = append(notes, "package detection failed: "+err.Error())
		partial = true
	}
	if packages == nil {
		packages = map[string]bool{}
	}

	// Step 2: probe PyTorch
	if packages["torch"] {
		pt, stderrPreview, err := c.probePyTorch(ctx, pythonPath)
		if err != nil || pt == nil {
			if err != nil {
				notes = append(notes, "PyTorch probe failed: "+err.Error())
			} else {
				notes = append(notes, "PyTorch probe exited with error")
			}
			partial = true
			if stderrPreview != "" {
				evidence = append(evidence, schema.Evidence{
					Source: "ml_pytorch_stderr_preview",
					Value:  stderrPreview,
				})
			}
		} else {
			info.PyTorch = pt
		}
	}

	// Step 3: probe TensorFlow
	if packages["tensorflow"] {
		tf, stderrPreview, err := c.probeTensorFlow(ctx, pythonPath)
		if err != nil || tf == nil {
			if err != nil {
				notes = append(notes, "TensorFlow probe failed: "+err.Error())
			} else {
				notes = append(notes, "TensorFlow probe exited with error")
			}
			partial = true
			if stderrPreview != "" {
				evidence = append(evidence, schema.Evidence{
					Source: "ml_tensorflow_stderr_preview",
					Value:  stderrPreview,
				})
			}
		} else {
			info.TensorFlow = tf
		}
	}

	// Step 4: probe JAX
	if packages["jax"] {
		jax, stderrPreview, err := c.probeJAX(ctx, pythonPath)
		if err != nil || jax == nil {
			if err != nil {
				notes = append(notes, "JAX probe failed: "+err.Error())
			} else {
				notes = append(notes, "JAX probe exited with error")
			}
			partial = true
			if stderrPreview != "" {
				evidence = append(evidence, schema.Evidence{
					Source: "ml_jax_stderr_preview",
					Value:  stderrPreview,
				})
			}
		} else {
			info.JAX = jax
		}
	}

	// Flatten to evidence
	if info.PyTorch != nil {
		evidence = append(evidence, schema.Evidence{Source: "ml_pytorch_version", Value: info.PyTorch.Version})
		evidence = append(evidence, schema.Evidence{Source: "ml_pytorch_cuda_available", Value: strconv.FormatBool(info.PyTorch.CUDAAvailable)})
		if info.PyTorch.CUDAVersion != "" {
			evidence = append(evidence, schema.Evidence{Source: "ml_pytorch_cuda_version", Value: info.PyTorch.CUDAVersion})
		}
		evidence = append(evidence, schema.Evidence{Source: "ml_pytorch_gpu_count", Value: strconv.Itoa(info.PyTorch.DeviceCount)})
	}
	if info.TensorFlow != nil {
		evidence = append(evidence, schema.Evidence{Source: "ml_tensorflow_version", Value: info.TensorFlow.Version})
		evidence = append(evidence, schema.Evidence{Source: "ml_tensorflow_gpu_count", Value: strconv.Itoa(info.TensorFlow.GPUCount)})
	}
	if info.JAX != nil {
		evidence = append(evidence, schema.Evidence{Source: "ml_jax_version", Value: info.JAX.Version})
		evidence = append(evidence, schema.Evidence{Source: "ml_jax_gpu_count", Value: strconv.Itoa(info.JAX.GPUCount)})
	}

	applicable := info.PyTorch != nil || info.TensorFlow != nil || info.JAX != nil
	if !applicable {
		notes = append(notes, "no ML frameworks detected")
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

func defaultPythonFinder() string {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// detectPackages returns a map of package names to bool (importable or not).
func (c *Collector) detectPackages(ctx context.Context, pythonPath string) (map[string]bool, error) {
	script := `import importlib.util, json
print(json.dumps({
    "torch": importlib.util.find_spec("torch") is not None,
    "tensorflow": importlib.util.find_spec("tensorflow") is not None,
    "jax": importlib.util.find_spec("jax") is not None
}))`

	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	res := c.Runner.Run(cmdCtx, pythonPath, "-c", script)
	cancel()

	if res.ExitCode != 0 {
		return nil, nil // Python may be broken; treat as no packages
	}

	var result map[string]bool
	if err := json.Unmarshal([]byte(res.Stdout), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Collector) probePyTorch(ctx context.Context, pythonPath string) (*PyTorchInfo, string, error) {
	script := `import json, torch
devices = []
if torch.cuda.is_available():
    devices = [torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())]
print(json.dumps({
    "version": torch.__version__,
    "cuda_available": torch.cuda.is_available(),
    "cuda_version": str(torch.version.cuda) if torch.version.cuda else None,
    "device_count": torch.cuda.device_count(),
    "devices": devices
}))`

	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	res := c.Runner.Run(cmdCtx, pythonPath, "-c", script)
	cancel()

	stderrPreview := ""
	if res.Stderr != "" {
		stderrPreview = truncate(res.Stderr, 200)
	}

	if res.ExitCode != 0 {
		return nil, stderrPreview, nil
	}

	var raw struct {
		Version       string   `json:"version"`
		CUDAAvailable bool     `json:"cuda_available"`
		CUDAVersion   *string  `json:"cuda_version"`
		DeviceCount   int      `json:"device_count"`
		Devices       []string `json:"devices"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
		return nil, stderrPreview, err
	}

	info := &PyTorchInfo{
		Version:       raw.Version,
		CUDAAvailable: raw.CUDAAvailable,
		DeviceCount:   raw.DeviceCount,
		Devices:       raw.Devices,
	}
	if raw.CUDAVersion != nil {
		info.CUDAVersion = *raw.CUDAVersion
	}
	return info, stderrPreview, nil
}

func (c *Collector) probeTensorFlow(ctx context.Context, pythonPath string) (*TensorFlowInfo, string, error) {
	script := `import json, tensorflow as tf
print(json.dumps({
    "version": tf.__version__,
    "gpu_count": len(tf.config.list_physical_devices('GPU'))
}))`

	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	res := c.Runner.Run(cmdCtx, pythonPath, "-c", script)
	cancel()

	stderrPreview := ""
	if res.Stderr != "" {
		stderrPreview = truncate(res.Stderr, 200)
	}

	if res.ExitCode != 0 {
		return nil, stderrPreview, nil
	}

	var raw struct {
		Version  string `json:"version"`
		GPUCount int    `json:"gpu_count"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
		return nil, stderrPreview, err
	}

	return &TensorFlowInfo{
		Version:  raw.Version,
		GPUCount: raw.GPUCount,
	}, stderrPreview, nil
}

func (c *Collector) probeJAX(ctx context.Context, pythonPath string) (*JAXInfo, string, error) {
	script := `import json, jax
gpu_count = len([d for d in jax.devices() if getattr(d, 'platform', '') == 'gpu'])
print(json.dumps({
    "version": jax.__version__,
    "gpu_count": gpu_count
}))`

	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	res := c.Runner.Run(cmdCtx, pythonPath, "-c", script)
	cancel()

	stderrPreview := ""
	if res.Stderr != "" {
		stderrPreview = truncate(res.Stderr, 200)
	}

	if res.ExitCode != 0 {
		return nil, stderrPreview, nil
	}

	var raw struct {
		Version  string `json:"version"`
		GPUCount int    `json:"gpu_count"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
		return nil, stderrPreview, err
	}

	return &JAXInfo{
		Version:  raw.Version,
		GPUCount: raw.GPUCount,
	}, stderrPreview, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "..."
}
