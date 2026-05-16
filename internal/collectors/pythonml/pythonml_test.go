package pythonml

import (
	"context"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollectorNoPython(t *testing.T) {
	c := &Collector{
		Runner:       cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{}),
		pythonFinder: func() string { return "" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false")
	}
}

func TestCollectorNoPackages(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"python3 -c import importlib.util, json\nprint(json.dumps({\n    \"torch\": importlib.util.find_spec(\"torch\") is not None,\n    \"tensorflow\": importlib.util.find_spec(\"tensorflow\") is not None,\n    \"jax\": importlib.util.find_spec(\"jax\") is not None\n}))": {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"torch": false, "tensorflow": false, "jax": false}`,
			},
		}),
		pythonFinder: func() string { return "python3" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false")
	}
}

func TestCollectorPyTorchCUDA(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			detectionKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"torch": true, "tensorflow": false, "jax": false}`,
			},
			pytorchKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"version": "2.3.0", "cuda_available": true, "cuda_version": "12.1", "device_count": 1, "devices": ["NVIDIA GeForce RTX 4090"]}`,
			},
		}),
		pythonFinder: func() string { return "python3" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || !*res.Applicable {
		t.Fatal("expected Applicable=true")
	}
	assertEvidence(t, res.Evidence, "ml_pytorch_version", "2.3.0")
	assertEvidence(t, res.Evidence, "ml_pytorch_cuda_available", "true")
	assertEvidence(t, res.Evidence, "ml_pytorch_cuda_version", "12.1")
	assertEvidence(t, res.Evidence, "ml_pytorch_gpu_count", "1")
}

func TestCollectorPyTorchCPUOnly(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			detectionKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"torch": true, "tensorflow": false, "jax": false}`,
			},
			pytorchKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"version": "2.3.0+cpu", "cuda_available": false, "cuda_version": null, "device_count": 0, "devices": []}`,
			},
		}),
		pythonFinder: func() string { return "python3" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "ml_pytorch_cuda_available", "false")
	assertEvidence(t, res.Evidence, "ml_pytorch_gpu_count", "0")
}

func TestCollectorPyTorchImportError(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			detectionKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"torch": true, "tensorflow": false, "jax": false}`,
			},
			pytorchKey(): {
				Command:  "python3",
				ExitCode: 1,
				Stderr:   "ImportError: libcudart.so.12: cannot open shared object file: No such file or directory",
			},
		}),
		pythonFinder: func() string { return "python3" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Partial {
		t.Fatal("expected Partial=true")
	}
	assertEvidence(t, res.Evidence, "ml_pytorch_stderr_preview", "ImportError: libcudart.so.12: cannot open shared object file: No such file or directory")
}

func TestCollectorTensorFlow(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			detectionKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"torch": false, "tensorflow": true, "jax": false}`,
			},
			tensorflowKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"version": "2.16.1", "gpu_count": 2}`,
			},
		}),
		pythonFinder: func() string { return "python3" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "ml_tensorflow_version", "2.16.1")
	assertEvidence(t, res.Evidence, "ml_tensorflow_gpu_count", "2")
}

func TestCollectorJAX(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			detectionKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"torch": false, "tensorflow": false, "jax": true}`,
			},
			jaxKey(): {
				Command:  "python3",
				ExitCode: 0,
				Stdout:   `{"version": "0.4.28", "gpu_count": 1}`,
			},
		}),
		pythonFinder: func() string { return "python3" },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "ml_jax_version", "0.4.28")
	assertEvidence(t, res.Evidence, "ml_jax_gpu_count", "1")
}

// Key builders must match the exact script string used in the collector.
func detectionKey() string {
	return "python3 -c import importlib.util, json\nprint(json.dumps({\n    \"torch\": importlib.util.find_spec(\"torch\") is not None,\n    \"tensorflow\": importlib.util.find_spec(\"tensorflow\") is not None,\n    \"jax\": importlib.util.find_spec(\"jax\") is not None\n}))"
}

func pytorchKey() string {
	return "python3 -c import json, torch\ndevices = []\nif torch.cuda.is_available():\n    devices = [torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())]\nprint(json.dumps({\n    \"version\": torch.__version__,\n    \"cuda_available\": torch.cuda.is_available(),\n    \"cuda_version\": str(torch.version.cuda) if torch.version.cuda else None,\n    \"device_count\": torch.cuda.device_count(),\n    \"devices\": devices\n}))"
}

func tensorflowKey() string {
	return "python3 -c import json, tensorflow as tf\nprint(json.dumps({\n    \"version\": tf.__version__,\n    \"gpu_count\": len(tf.config.list_physical_devices('GPU'))\n}))"
}

func jaxKey() string {
	return "python3 -c import json, jax\ngpu_count = len([d for d in jax.devices() if getattr(d, 'platform', '') == 'gpu'])\nprint(json.dumps({\n    \"version\": jax.__version__,\n    \"gpu_count\": gpu_count\n}))"
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
