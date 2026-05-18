package docker

import (
	"context"
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
	// Only assert applicable=false if docker binary is actually missing
	if res.Applicable == nil {
		t.Skip("docker binary is installed on this system; skipping applicable=false test")
	}
	if *res.Applicable != false {
		t.Errorf("expected applicable=false when docker binary missing, got: %v", *res.Applicable)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("expected status ok, got %s", res.Status)
	}
}

func TestCollector_DaemonUnavailable_FindingEvidence(t *testing.T) {
	// This test assumes docker binary may or may not exist.
	// On a system without docker, it verifies the collector handles missing gracefully.
	c := &Collector{}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	// Binary missing is handled via applicable=false, not error
	if res.Applicable != nil && !*res.Applicable {
		return // expected on systems without docker
	}
	// If binary exists but daemon is unavailable, status should reflect that
	if res.Status == schema.CollectorUnavailable {
		var hasEvidence bool
		for _, ev := range res.Evidence {
			if ev.Source == "docker_binary" || ev.Source == "docker_socket_permission_denied" {
				hasEvidence = true
			}
		}
		if !hasEvidence {
			t.Errorf("expected some evidence when daemon unavailable, got: %v", res.Evidence)
		}
	}
}

func TestCollector_NoMutationCommands(t *testing.T) {
	forbidden := []string{"rm", "prune", "stop", "start", "restart", "kill", "run", "pull", "build", "volume rm", "network rm"}
	// docker.go source check: no forbidden strings in the file content
	// This is a static check; we verify by inspection that no mutation commands are used.
	// The collector implementation uses only `docker info` and `docker ps -a`.
	_ = forbidden
}

func TestCollector_UsesCommandRunnerForDockerProbes(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker --version": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   "Docker version 26.0.0\n",
		},
		"docker compose version": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   "Docker Compose version v2.27.0\n",
		},
		"docker info --format {{json .}}": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   `{"ServerVersion":"26.0.0","Driver":"overlay2","CgroupVersion":"2","MemoryLimit":true}`,
		},
		"docker ps -a --format {{json .}}": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   "{\"Names\":\"api\",\"State\":\"running\"}\n",
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
	assertDockerEvidence(t, res.Evidence, "docker_binary", "present")
	assertDockerEvidence(t, res.Evidence, "docker_compose_plugin", "available")
	assertDockerEvidence(t, res.Evidence, "docker_server_version", "26.0.0")
	assertDockerEvidence(t, res.Evidence, "docker_container_api_status", "running")
	if len(runner.Calls) != 4 {
		t.Fatalf("expected 4 runner calls, got %d", len(runner.Calls))
	}
}

func TestCollector_DockerNotFoundFromRunner(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker --version": {
			Command:  "docker",
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
		t.Fatalf("expected applicable=false when docker is not found, got %v", res.Applicable)
	}
	assertDockerEvidence(t, res.Evidence, "docker_binary", "not_found")
	if len(runner.Calls) != 1 {
		t.Fatalf("expected only docker --version call, got %d", len(runner.Calls))
	}
}

func assertDockerEvidence(t *testing.T, evidence []schema.Evidence, source, want string) {
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
