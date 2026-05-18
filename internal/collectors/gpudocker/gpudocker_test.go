package gpudocker

import (
	"context"
	"os"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollectorNoToolkit(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"ServerVersion":"24.0.5"}`,
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false")
	}
	assertEvidence(t, res.Evidence, "docker_binary_present", "true")
	assertEvidence(t, res.Evidence, "docker_daemon_accessible", "true")
	assertEvidence(t, res.Evidence, "docker_installed", "true")
	assertEvidence(t, res.Evidence, "docker_gpu_runtime_present", "false")
}

func TestCollectorDockerInfoWithNvidiaRuntime(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Runtimes":{"nvidia":{"path":"nvidia-container-runtime"}}}`,
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || !*res.Applicable {
		t.Fatal("expected Applicable=true")
	}
	assertEvidence(t, res.Evidence, "docker_binary_present", "true")
	assertEvidence(t, res.Evidence, "docker_daemon_accessible", "true")
	assertEvidence(t, res.Evidence, "docker_gpu_runtime_present", "true")
	assertEvidence(t, res.Evidence, "docker_gpu_runtime_name", "nvidia")
}

func TestCollectorToolkitPresent(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				ExitCode: 0,
				Stdout:   "nvidia-ctk version 1.14.0\n",
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Runtimes":{}}`,
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "nvidia_container_toolkit_version", "nvidia-ctk version 1.14.0")
}

func TestCollectorGPUVerifySuccess(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Runtimes":{}}`,
			},
			"docker image inspect nvidia/cuda:12.2.0-base-ubuntu22.04": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   "[{\"Id\":\"sha256:...\"}]",
			},
			"docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   "GPU 0: NVIDIA GeForce RTX 4090",
			},
		}),
		GPUVerify: true,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "docker_gpu_verify_result", "success")
}

func TestCollectorGPUVerifyImageMissingNoPull(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Runtimes":{}}`,
			},
			"docker image inspect nvidia/cuda:12.2.0-base-ubuntu22.04": {
				Command:  "docker",
				ExitCode: 1,
				Stderr:   "Error: No such image",
			},
		}),
		GPUVerify: true,
		AllowPull: false,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "docker_gpu_verify_result", "image_missing")
}

func TestCollectorGPUVerifyNotRun(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Runtimes":{}}`,
			},
		}),
		GPUVerify: false,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, ev := range res.Evidence {
		if ev.Source == "docker_gpu_verify_result" {
			t.Fatalf("expected no verify result evidence, got %q", ev.Value)
		}
	}
}

func TestCollectorDockerBinaryNotFound(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				NotFound: true,
				ExitCode: -1,
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "docker_binary_present", "false")
	for _, ev := range res.Evidence {
		if ev.Source == "docker_daemon_accessible" {
			t.Fatalf("expected no daemon_accessible evidence when binary is missing, got %q", ev.Value)
		}
	}
}

func TestCollectorDockerDaemonDown(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 1,
				Stderr:   "Cannot connect to the Docker daemon",
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "docker_binary_present", "true")
	assertEvidence(t, res.Evidence, "docker_daemon_accessible", "false")
}

func TestCollectorNvidiaCtkTimeoutMarksCollectorTimeout(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				ExitCode: -1,
				TimedOut: true,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				NotFound: true,
				ExitCode: -1,
			},
		}),
	}

	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertTimeoutResult(t, res, 1000, "nvidia-ctk --version timed out")
	assertEvidence(t, res.Evidence, "gpudocker_probe_timeout", "nvidia-ctk --version")
}

func TestCollectorDockerInfoTimeoutMarksCollectorTimeout(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: -1,
				TimedOut: true,
			},
		}),
	}

	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertTimeoutResult(t, res, 1500, "docker info --format {{json .}} timed out")
	assertEvidence(t, res.Evidence, "gpudocker_probe_timeout", "docker info --format {{json .}}")
}

func TestCollectorGPUVerifyTimeoutMarksCollectorTimeout(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-ctk --version": {
				Command:  "nvidia-ctk",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-cli --version": {
				Command:  "nvidia-container-cli",
				NotFound: true,
				ExitCode: -1,
			},
			"nvidia-container-runtime --version": {
				Command:  "nvidia-container-runtime",
				NotFound: true,
				ExitCode: -1,
			},
			"docker info --format {{json .}}": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Runtimes":{}}`,
			},
			"docker image inspect nvidia/cuda:12.2.0-base-ubuntu22.04": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   "[{\"Id\":\"sha256:...\"}]",
			},
			"docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi": {
				Command:  "docker",
				ExitCode: -1,
				TimedOut: true,
			},
		}),
		GPUVerify: true,
	}

	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertTimeoutResult(t, res, 5000, "docker run --gpus all timed out")
	assertEvidence(t, res.Evidence, "docker_gpu_verify_result", "timeout")
	assertEvidence(t, res.Evidence, "gpudocker_probe_timeout", "docker run --gpus all")
}

func TestExtractDockerGPURuntime(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`{"Runtimes":{"nvidia":{"path":"nvidia-container-runtime"}}}`, "nvidia"},
		{`{"Runtimes":{}}`, ""},
		{`{"ServerVersion":"24.0.5"}`, ""},
		{`{"DefaultRuntime":"nvidia"}`, "nvidia"},
		{`{"DefaultRuntime":"nvidia-container-runtime"}`, "nvidia-container-runtime"},
	}
	for _, tt := range tests {
		got := extractDockerGPURuntime(tt.input)
		if got != tt.want {
			t.Fatalf("extractDockerGPURuntime(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractDaemonJSONRuntime(t *testing.T) {
	// Create a temp daemon.json
	f, err := os.CreateTemp("", "daemon-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `{"runtimes":{"nvidia":{"path":"nvidia-container-runtime"}}}`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f.Close()

	got := extractDaemonJSONRuntime(f.Name())
	if got != "nvidia" {
		t.Fatalf("extractDaemonJSONRuntime = %q, want nvidia", got)
	}

	// Missing file
	if got := extractDaemonJSONRuntime("/nonexistent/daemon.json"); got != "" {
		t.Fatalf("expected empty for missing file, got %q", got)
	}
}

func assertEvidence(t *testing.T, evidence []schema.Evidence, source, want string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source {
			if ev.Value != want {
				t.Fatalf("evidence %q = %q, want %q", source, ev.Value, want)
			}
			return
		}
	}
	t.Fatalf("missing evidence %q (want %q)", source, want)
}

func assertTimeoutResult(t *testing.T, res schema.CollectorResult, timeoutMs int, note string) {
	t.Helper()
	if res.Status != schema.CollectorTimeout {
		t.Fatalf("status = %s, want timeout", res.Status)
	}
	if !res.Partial {
		t.Fatal("expected Partial=true")
	}
	if res.TimeoutMs != timeoutMs {
		t.Fatalf("TimeoutMs = %d, want %d", res.TimeoutMs, timeoutMs)
	}
	for _, got := range res.Notes {
		if got == note {
			return
		}
	}
	t.Fatalf("missing timeout note %q in %v", note, res.Notes)
}
