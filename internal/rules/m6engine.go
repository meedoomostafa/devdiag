package rules

import (
	"strconv"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// M6Engine evaluates M6 GPU/ML/container/cache findings.
type M6Engine struct{}

// NewM6Engine creates a new M6 policy engine.
func NewM6Engine() *M6Engine {
	return &M6Engine{}
}

// Evaluate implements the PolicyEngine interface for M6.
func (e *M6Engine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	var findings []schema.Finding

	// Build an evidence map for quick lookups
	evMap := make(map[string]string)
	for _, result := range snapshot.Collectors {
		for _, ev := range result.Evidence {
			evMap[ev.Source] = ev.Value
		}
	}

	gpuPresent := evMap["gpu_present"] == "true"
	gpuHardware := evMap["gpu_hardware_detected"] == "true"
	moduleLoaded := evMap["gpu_nvidia_module_loaded"] == "true"
	nvidiaSMIStatus := evMap["gpu_nvidia_smi_status"]
	secureBootStr := evMap["gpu_secure_boot_enabled"]
	pytorchVersion := evMap["ml_pytorch_version"]
	pytorchCUDA := evMap["ml_pytorch_cuda_available"] == "true"
	pytorchGPUCount, _ := strconv.Atoi(evMap["ml_pytorch_gpu_count"])
	tfVersion := evMap["ml_tensorflow_version"]
	tfGPUCount, _ := strconv.Atoi(evMap["ml_tensorflow_gpu_count"])
	jaxVersion := evMap["ml_jax_version"]
	jaxGPUCount, _ := strconv.Atoi(evMap["ml_jax_gpu_count"])
	dockerBinaryPresent := evMap["docker_binary_present"] == "true"
	dockerDaemonAccessible := evMap["docker_daemon_accessible"] == "true"
	dockerGPURuntime := evMap["docker_gpu_runtime_present"] == "true"
	dockerGPUVerify := evMap["docker_gpu_verify_result"]
	toolkitVersion := evMap["nvidia_container_toolkit_version"]

	// F-GPU-001: NVIDIA hardware present but driver unavailable
	if gpuHardware && (!moduleLoaded || (!gpuPresent && nvidiaSMIDriverUnavailable(nvidiaSMIStatus))) {
		symptom := "NVIDIA GPU detected but kernel module is not loaded"
		likelyCauses := []string{"NVIDIA driver not installed", "Driver version incompatible with kernel", "Secure Boot blocking unsigned module"}
		if moduleLoaded {
			symptom = "NVIDIA hardware and kernel module are present, but nvidia-smi could not enumerate GPUs"
			likelyCauses = []string{"NVIDIA user-space driver libraries may not match the loaded kernel module", "Driver stack may be partially installed or unhealthy", "GPU device nodes may be inaccessible"}
		}
		findings = append(findings, schema.Finding{
			ID:           "F-GPU-001",
			Title:        "NVIDIA hardware present but driver unavailable",
			Severity:     schema.SeverityHigh,
			Confidence:   0.8,
			Symptom:      symptom,
			LikelyCauses: likelyCauses,
			FixHints:     []string{"install-nvidia-driver"},
		})
	}

	// F-GPU-002: Secure Boot may be blocking NVIDIA module
	if secureBootStr == "true" && !moduleLoaded && gpuHardware {
		findings = append(findings, schema.Finding{
			ID:           "F-GPU-002",
			Title:        "Secure Boot may be blocking NVIDIA module",
			Severity:     schema.SeverityMedium,
			Confidence:   0.6,
			Symptom:      "Secure Boot is enabled and NVIDIA kernel module is not loaded",
			LikelyCauses: []string{"NVIDIA kernel module may not be signed for Secure Boot", "Module signing key not enrolled in MOK"},
			FixHints:     []string{"disable-secure-boot-or-sign-module"},
		})
	}

	// F-ML-PYTORCH-001: PyTorch installed with CPU-only build in GPU project
	if pytorchVersion != "" && !pytorchCUDA && gpuPresent {
		findings = append(findings, schema.Finding{
			ID:           "F-ML-PYTORCH-001",
			Title:        "PyTorch installed with CPU-only build in GPU project",
			Severity:     schema.SeverityMedium,
			Confidence:   0.75,
			Symptom:      "PyTorch is installed but CUDA is not available while a GPU is present",
			LikelyCauses: []string{"Installed CPU-only PyTorch wheel", "Missing CUDA runtime libraries"},
			FixHints:     []string{"install-pytorch-cuda"},
		})
	}

	// F-ML-PYTORCH-002: PyTorch CUDA build installed but GPU unavailable
	if pytorchVersion != "" && pytorchCUDA && pytorchGPUCount == 0 {
		findings = append(findings, schema.Finding{
			ID:           "F-ML-PYTORCH-002",
			Title:        "PyTorch CUDA build installed but GPU unavailable",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "PyTorch reports CUDA available but no GPU devices are visible",
			LikelyCauses: []string{"NVIDIA driver issue", "GPU is in compute-exclusive mode", "Container lacks GPU access"},
			FixHints:     []string{"check-nvidia-driver"},
		})
	}

	// F-ML-TF-001: TensorFlow installed but no GPU visible
	if tfVersion != "" && tfGPUCount == 0 && gpuPresent {
		findings = append(findings, schema.Finding{
			ID:           "F-ML-TF-001",
			Title:        "TensorFlow installed but no GPU visible",
			Severity:     schema.SeverityMedium,
			Confidence:   0.6,
			Symptom:      "TensorFlow is installed but no GPU devices are detected",
			LikelyCauses: []string{"TensorFlow CPU-only build", "Missing NVIDIA libraries", "Driver version incompatible"},
			FixHints:     []string{"install-tensorflow-gpu"},
		})
	}

	// F-ML-JAX-001: JAX installed but no GPU visible
	if jaxVersion != "" && jaxGPUCount == 0 && gpuPresent {
		findings = append(findings, schema.Finding{
			ID:           "F-ML-JAX-001",
			Title:        "JAX installed but no GPU visible",
			Severity:     schema.SeverityMedium,
			Confidence:   0.6,
			Symptom:      "JAX is installed but no GPU devices are detected",
			LikelyCauses: []string{"JAX CPU-only build", "Missing CUDA/cuDNN libraries"},
			FixHints:     []string{"install-jax-cuda"},
		})
	}

	// F-DOCKER-GPU-001: Host GPU visible but Docker GPU runtime unavailable
	// Only fire when Docker binary is present AND daemon is accessible.
	// Avoids false positive when Docker is not installed or daemon is down.
	if gpuPresent && dockerBinaryPresent && dockerDaemonAccessible && !dockerGPURuntime && toolkitVersion == "" {
		findings = append(findings, schema.Finding{
			ID:           "F-DOCKER-GPU-001",
			Title:        "Host GPU visible but Docker GPU runtime unavailable",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "NVIDIA GPU is present but Docker cannot access it",
			LikelyCauses: []string{"NVIDIA Container Toolkit not installed", "Docker daemon not configured with nvidia runtime"},
			FixHints:     []string{"install-nvidia-toolkit"},
		})
	}

	// F-DOCKER-GPU-002: Container GPU verification failed
	if dockerGPUVerify == "failed" || dockerGPUVerify == "timeout" {
		findings = append(findings, schema.Finding{
			ID:           "F-DOCKER-GPU-002",
			Title:        "Container GPU verification failed",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "Docker GPU container could not run nvidia-smi successfully",
			LikelyCauses: []string{"NVIDIA Container Toolkit misconfigured", "Image incompatible with host driver"},
			FixHints:     []string{"install-nvidia-toolkit"},
		})
	}

	// F-CACHE-001: Package cache not writable
	for _, tool := range []string{"pip", "uv", "poetry", "npm", "pnpm", "go"} {
		writableKey := "cache_" + tool + "_writable"
		pathKey := "cache_" + tool + "_path"
		if evMap[writableKey] == "false" && evMap[pathKey] != "" {
			findings = append(findings, schema.Finding{
				ID:           "F-CACHE-001",
				Title:        "Package cache not writable",
				Severity:     schema.SeverityLow,
				Confidence:   0.7,
				Symptom:      tool + " cache directory is not writable by current user",
				LikelyCauses: []string{"Cache owned by root or another user"},
				FixHints:     []string{"fix-cache-permissions"},
				Evidence: []schema.Evidence{
					{Source: "cache_tool", Value: tool},
					{Source: "cache_path", Value: evMap[pathKey]},
				},
			})
		}
	}

	// F-CACHE-002: Package cache appears root-owned
	for _, tool := range []string{"pip", "uv", "poetry", "npm", "pnpm", "go"} {
		uidKey := "cache_" + tool + "_owner_uid"
		pathKey := "cache_" + tool + "_path"
		if evMap[pathKey] != "" {
			uidStr, ok := evMap[uidKey]
			if !ok || uidStr == "" {
				continue
			}
			uid, err := strconv.Atoi(uidStr)
			if err == nil && uid == 0 {
				findings = append(findings, schema.Finding{
					ID:           "F-CACHE-002",
					Title:        "Package cache appears root-owned",
					Severity:     schema.SeverityLow,
					Confidence:   0.7,
					Symptom:      tool + " cache directory is owned by root",
					LikelyCauses: []string{"Cache was created by a previous sudo/root package-manager invocation"},
					FixHints:     []string{"fix-cache-permissions"},
					Evidence: []schema.Evidence{
						{Source: "cache_tool", Value: tool},
						{Source: "cache_path", Value: evMap[pathKey]},
						{Source: "cache_owner_uid", Value: "0"},
					},
				})
			}
		}
	}

	// F-CACHE-003: Docker cache unusually large
	dockerSize := evMap["cache_docker_size_mb"]
	if dockerSize != "" && dockerSize != "unknown" {
		// Simple heuristic: any Docker cache presence is noted; size evaluation is manual
		findings = append(findings, schema.Finding{
			ID:           "F-CACHE-003",
			Title:        "Docker cache present",
			Severity:     schema.SeverityLow,
			Confidence:   0.5,
			Symptom:      "Docker cache size: " + dockerSize,
			LikelyCauses: []string{"Accumulated image layers and build cache"},
			FixHints:     []string{"warn-docker-cleanup"},
		})
	}

	return findings, nil
}

func nvidiaSMIDriverUnavailable(status string) bool {
	switch status {
	case "error", "permission_denied", "timeout", "parse_error":
		return true
	default:
		return false
	}
}
