package gpu

import (
	"context"
	"os"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollectorNoNvidiaSMI(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:  "nvidia-smi",
				NotFound: true,
				ExitCode: -1,
			},
			"lspci": {
				Command:  "lspci",
				NotFound: true,
				ExitCode: -1,
			},
		}),
		procPathChecker: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("expected status ok, got %s", res.Status)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false")
	}
	assertEvidence(t, res.Evidence, "gpu_present", "false")
	assertEvidence(t, res.Evidence, "gpu_hardware_detected", "false")
}

func TestCollectorOneGPU(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:  "nvidia-smi",
				ExitCode: 0,
				Stdout:   "0, NVIDIA GeForce RTX 4090, 550.120, 24576\n",
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("expected status ok, got %s", res.Status)
	}
	if res.Applicable == nil || !*res.Applicable {
		t.Fatal("expected Applicable=true")
	}
	assertEvidence(t, res.Evidence, "gpu_present", "true")
	assertEvidence(t, res.Evidence, "gpu_count", "1")
	assertEvidence(t, res.Evidence, "gpu_0_name", "NVIDIA GeForce RTX 4090")
	assertEvidence(t, res.Evidence, "gpu_0_driver_version", "550.120")
	assertEvidence(t, res.Evidence, "gpu_0_vram_mb", "24576")
}

func TestCollectorMultiGPU(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:  "nvidia-smi",
				ExitCode: 0,
				Stdout: "0, NVIDIA A100-SXM4-40GB, 535.104, 40960\n" +
					"1, NVIDIA A100-SXM4-40GB, 535.104, 40960\n",
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "gpu_count", "2")
	assertEvidence(t, res.Evidence, "gpu_0_name", "NVIDIA A100-SXM4-40GB")
	assertEvidence(t, res.Evidence, "gpu_1_name", "NVIDIA A100-SXM4-40GB")
}

func TestCollectorTimeout(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:  "nvidia-smi",
				TimedOut: true,
				ExitCode: -1,
			},
			"lspci": {
				Command:  "lspci",
				NotFound: true,
				ExitCode: -1,
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != schema.CollectorTimeout {
		t.Fatalf("expected status timeout, got %s", res.Status)
	}
	if !res.Partial {
		t.Fatal("expected Partial=true")
	}
}

func TestCollectorMalformedCSV(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:  "nvidia-smi",
				ExitCode: 0,
				Stdout:   "garbage line\nanother bad line\n",
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Partial {
		t.Fatal("expected Partial=true for malformed output")
	}
}

func TestCollectorPermissionDenied(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:          "nvidia-smi",
				ExitCode:         1,
				Stderr:           "permission denied accessing NVIDIA device",
				PermissionDenied: true,
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != schema.CollectorPermissionDenied {
		t.Fatalf("expected status permission_denied, got %s", res.Status)
	}
	if !res.Partial {
		t.Fatal("expected Partial=true")
	}
}

func TestCollectorLSPCIFallback(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits": {
				Command:  "nvidia-smi",
				NotFound: true,
				ExitCode: -1,
			},
			"lspci": {
				Command:  "lspci",
				ExitCode: 0,
				Stdout:   "01:00.0 3D controller: NVIDIA Corporation GA102 [GeForce RTX 3090]\n",
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || !*res.Applicable {
		t.Fatal("expected Applicable=true from lspci fallback")
	}
	assertEvidence(t, res.Evidence, "gpu_hardware_detected", "true")
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

func TestParseNvidiaSMIOutput(t *testing.T) {
	stdout := "0, NVIDIA GeForce RTX 4090, 550.120, 24576\n" +
		"1, NVIDIA A100-SXM4-40GB, 535.104, 40960\n"
	devices, err := parseNvidiaSMIOutput(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	if devices[0].Index != 0 || devices[0].Name != "NVIDIA GeForce RTX 4090" || devices[0].DriverVersion != "550.120" || devices[0].VRAM_MB != 24576 {
		t.Fatalf("device[0] mismatch: %+v", devices[0])
	}
	if devices[1].Index != 1 || devices[1].Name != "NVIDIA A100-SXM4-40GB" || devices[1].DriverVersion != "535.104" || devices[1].VRAM_MB != 40960 {
		t.Fatalf("device[1] mismatch: %+v", devices[1])
	}
}

func TestParseNvidiaSMIOutputMalformed(t *testing.T) {
	// Malformed lines should be skipped; valid lines retained
	stdout := "bad line\n0, RTX 4090, 550.120, 24576\nanother bad\n"
	devices, err := parseNvidiaSMIOutput(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
}

func TestParseNvidiaSMIOutputQuotedFields(t *testing.T) {
	// GPU names with commas must be quoted per CSV spec
	stdout := `0, "NVIDIA RTX A6000, Ada Generation", 550.120, 49152`
	devices, err := parseNvidiaSMIOutput(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].Name != "NVIDIA RTX A6000, Ada Generation" {
		t.Fatalf("unexpected name: %q", devices[0].Name)
	}
	if devices[0].VRAM_MB != 49152 {
		t.Fatalf("unexpected vram: %d", devices[0].VRAM_MB)
	}
}

func TestParseNvidiaSMIOutputTooFewFields(t *testing.T) {
	stdout := "0, RTX 4090, 550.120\n"
	devices, err := parseNvidiaSMIOutput(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("expected 0 devices for short row, got %d", len(devices))
	}
}

func TestModuleLoaded(t *testing.T) {
	// /proc/modules may or may not contain nvidia on the host;
	// this test just ensures the function does not panic.
	c := &Collector{}
	_ = c.moduleLoaded()
}

func TestSecureBootStatus(t *testing.T) {
	// /sys/kernel/security/secureboot may not exist on all hosts;
	// this test just ensures the function does not panic.
	c := &Collector{}
	_ = c.secureBootStatus()
}

func BenchmarkParseNvidiaSMIOutput(b *testing.B) {
	stdout := "0, NVIDIA GeForce RTX 4090, 550.120, 24576\n"
	for i := 0; i < b.N; i++ {
		_, _ = parseNvidiaSMIOutput(stdout)
	}
}
