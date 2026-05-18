package podman

import (
	"context"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_BinaryMissing_ApplicableFalse(t *testing.T) {
	c := &Collector{}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	// Only assert applicable=false if podman binary is actually missing
	if res.Applicable == nil {
		t.Skip("podman binary is installed on this system; skipping applicable=false test")
	}
	if *res.Applicable != false {
		t.Errorf("expected applicable=false when podman binary missing, got: %v", *res.Applicable)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("expected status ok, got %s", res.Status)
	}
}

func TestCollector_DoesNotAssumeDockerSemantics(t *testing.T) {
	// Verify the podman collector does not reference docker-specific labels or commands
	c := &Collector{}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	for _, ev := range res.Evidence {
		if strings.Contains(ev.Source, "docker") {
			t.Errorf("podman collector should not emit docker-prefixed evidence: %s", ev.Source)
		}
	}
}

func TestCollector_UsesCommandRunnerForPodmanProbes(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"podman --version": {
			Command:  "podman",
			ExitCode: 0,
			Stdout:   "podman version 5.0.0\n",
		},
		"podman info --format json": {
			Command:  "podman",
			ExitCode: 0,
			Stdout: `{
				"host": {
					"remoteSocket": {"path": "/run/user/1000/podman/podman.sock"},
					"security": {"rootless": true, "uidmap": [{"container_id": 0}], "gidmap": [{"container_id": 0}]},
					"cgroupManager": "systemd"
				},
				"store": {"graphRoot": "/home/user/.local/share/containers/storage", "graphDriverName": "overlay"}
			}`,
		},
		"podman ps -a --format json": {
			Command:  "podman",
			ExitCode: 0,
			Stdout:   `[{"Names":["api"],"State":"running","Labels":{"app":"devdiag"}}]`,
		},
	})

	c := &Collector{Runner: runner}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %s, want ok", res.Status)
	}
	assertPodmanEvidence(t, res.Evidence, "podman_binary", "present")
	assertPodmanEvidence(t, res.Evidence, "podman_rootless", "true")
	assertPodmanEvidence(t, res.Evidence, "podman_container_api_status", "running")
	if len(runner.Calls) != 3 {
		t.Fatalf("expected 3 runner calls, got %d", len(runner.Calls))
	}
}

func TestCollector_PodmanNotFoundFromRunner(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"podman --version": {
			Command:  "podman",
			NotFound: true,
			ExitCode: -1,
		},
	})

	c := &Collector{Runner: runner}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatalf("expected applicable=false when podman is not found, got %v", res.Applicable)
	}
	assertPodmanEvidence(t, res.Evidence, "podman_binary", "not_found")
}

func assertPodmanEvidence(t *testing.T, evidence []schema.Evidence, source, want string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source {
			if ev.Value != want {
				t.Fatalf("evidence %q = %q, want %q", source, ev.Value, want)
			}
			return
		}
	}
	t.Fatalf("missing evidence %q", source)
}
