package rules

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func buildSnapshot(evidence map[string]string) graph.NormalizedSnapshot {
	var evs []schema.Evidence
	for k, v := range evidence {
		evs = append(evs, schema.Evidence{Source: k, Value: v})
	}
	return graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "gpu", Evidence: evs},
		},
	}
}

func TestM6EngineNoGPU(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":              "false",
		"gpu_hardware_detected":    "false",
		"gpu_nvidia_module_loaded": "false",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestM6EngineFGPU001(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":              "false",
		"gpu_hardware_detected":    "true",
		"gpu_nvidia_module_loaded": "false",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-GPU-001")
}

func TestM6EngineFGPU002(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":              "false",
		"gpu_hardware_detected":    "true",
		"gpu_nvidia_module_loaded": "false",
		"gpu_secure_boot_enabled":  "true",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-GPU-002")
	assertFinding(t, findings, "F-GPU-001")
}

func TestM6EngineNoFGPU002WhenModuleLoaded(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":              "true",
		"gpu_hardware_detected":    "true",
		"gpu_nvidia_module_loaded": "true",
		"gpu_secure_boot_enabled":  "true",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "F-GPU-002" {
			t.Fatal("expected no F-GPU-002 when module is loaded")
		}
	}
}

func TestM6EngineFMLPyTorch001(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":               "true",
		"ml_pytorch_version":        "2.3.0+cpu",
		"ml_pytorch_cuda_available": "false",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-ML-PYTORCH-001")
}

func TestM6EngineFMLPyTorch002(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":               "true",
		"ml_pytorch_version":        "2.3.0",
		"ml_pytorch_cuda_available": "true",
		"ml_pytorch_gpu_count":      "0",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-ML-PYTORCH-002")
}

func TestM6EngineFMLTF001(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":             "true",
		"ml_tensorflow_version":   "2.16.1",
		"ml_tensorflow_gpu_count": "0",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-ML-TF-001")
}

func TestM6EngineFMLJAX001(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":      "true",
		"ml_jax_version":   "0.4.28",
		"ml_jax_gpu_count": "0",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-ML-JAX-001")
}

func TestM6EngineFDockerGPU001(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":                      "true",
		"docker_binary_present":            "true",
		"docker_daemon_accessible":         "true",
		"docker_gpu_runtime_present":       "false",
		"nvidia_container_toolkit_version": "",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-DOCKER-GPU-001")
}

func TestM6EngineNoFDockerGPU001WhenDockerMissing(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":                      "true",
		"docker_binary_present":            "false",
		"docker_gpu_runtime_present":       "false",
		"nvidia_container_toolkit_version": "",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "F-DOCKER-GPU-001" {
			t.Fatal("expected no F-DOCKER-GPU-001 when Docker binary is not present")
		}
	}
}

func TestM6EngineNoFDockerGPU001WhenDockerDaemonDown(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":                      "true",
		"docker_binary_present":            "true",
		"docker_daemon_accessible":         "false",
		"docker_gpu_runtime_present":       "false",
		"nvidia_container_toolkit_version": "",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "F-DOCKER-GPU-001" {
			t.Fatal("expected no F-DOCKER-GPU-001 when Docker daemon is not accessible")
		}
	}
}

func TestM6EngineFDockerGPU002(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"docker_gpu_verify_result": "failed",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-DOCKER-GPU-002")
}

func TestM6EngineFDockerGPU002Timeout(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"docker_gpu_verify_result": "timeout",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-DOCKER-GPU-002")
}

func TestM6EngineFCache001(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"cache_pip_path":      "/home/user/.cache/pip",
		"cache_pip_writable":  "false",
		"cache_pip_owner_uid": "0",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-CACHE-001")
	assertFinding(t, findings, "F-CACHE-002")
}

func TestM6EngineFCache003(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"cache_docker_size_mb": "2.5GB",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFinding(t, findings, "F-CACHE-003")
}

func TestM6EngineHealthy(t *testing.T) {
	engine := NewM6Engine()
	snap := buildSnapshot(map[string]string{
		"gpu_present":                "true",
		"gpu_hardware_detected":      "true",
		"gpu_nvidia_module_loaded":   "true",
		"gpu_secure_boot_enabled":    "false",
		"ml_pytorch_version":         "2.3.0",
		"ml_pytorch_cuda_available":  "true",
		"ml_pytorch_gpu_count":       "1",
		"docker_gpu_runtime_present": "true",
	})
	findings, err := engine.Evaluate(snap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for healthy system, got %d", len(findings))
	}
}

func assertFinding(t *testing.T, findings []schema.Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return
		}
	}
	t.Fatalf("missing finding %s", id)
}
