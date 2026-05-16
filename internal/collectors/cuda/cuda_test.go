package cuda

import (
	"context"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollectorNVCCMissing(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvcc --version": {
				Command:  "nvcc",
				NotFound: true,
				ExitCode: -1,
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
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false")
	}
}

func TestCollectorNVCCTimeout(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvcc --version": {
				Command:  "nvcc",
				TimedOut: true,
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
}

func TestCollectorNVCCSuccess(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvcc --version": {
				Command:  "nvcc",
				ExitCode: 0,
				Stdout: "Cuda compilation tools, release 12.1, V12.1.105\n" +
					"Build cuda_12.1.r12.1/compiler.12345678_0\n",
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
	assertEvidence(t, res.Evidence, "cuda_runtime_version", "12.1")
}

func TestCollectorNVCCParseFailure(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"nvcc --version": {
				Command:  "nvcc",
				ExitCode: 0,
				Stdout:   "unexpected output without version\n",
			},
		}),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false when parse fails")
	}
}

func TestParseNVCCOutput(t *testing.T) {
	stdout := "Cuda compilation tools, release 12.1, V12.1.105\n"
	ver, err := parseNVCCOutput(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "12.1" {
		t.Fatalf("expected version 12.1, got %q", ver)
	}
}

func TestParseNVCCOutputMissing(t *testing.T) {
	stdout := "some other text without release info\n"
	ver, err := parseNVCCOutput(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "" {
		t.Fatalf("expected empty version, got %q", ver)
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
