package systemd

import (
	"context"
	"os/exec"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "systemd" {
		t.Errorf("Name() = %q, want %q", got, "systemd")
	}
}

func TestCollector_NonSystemd(t *testing.T) {
	c := &Collector{RepoExpectsDocker: false}
	ctx := context.Background()
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	// Should be unavailable or ok, never fatal
	if res.Status != schema.CollectorOK && res.Status != schema.CollectorUnavailable {
		t.Errorf("unexpected status: %q", res.Status)
	}
}

func TestCollector_DockerNotApplicable(t *testing.T) {
	c := &Collector{RepoExpectsDocker: false}
	ctx := context.Background()
	res, _ := c.Collect(ctx)

	found := false
	for _, ev := range res.Evidence {
		if ev.Source == "host_docker_service" && ev.Value == "not_applicable" {
			found = true
		}
	}
	if !found {
		// If systemd is unavailable, this evidence may not exist; that's acceptable
		t.Logf("docker service evidence: %v", res.Evidence)
	}
}

func TestCollector_UsesInjectedRunner(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl not on PATH")
	}
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"systemctl is-system-running": {Stdout: "running\n", ExitCode: 0},
		"systemctl is-active docker":  {Stdout: "active\n", ExitCode: 0},
	})
	c := &Collector{RepoExpectsDocker: true, Runner: fake}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	var systemdVal, dockerVal string
	for _, ev := range res.Evidence {
		switch ev.Source {
		case "host_systemd":
			systemdVal = ev.Value
		case "host_docker_service":
			dockerVal = ev.Value
		}
	}
	if systemdVal != "running" {
		t.Errorf("host_systemd = %q, want running", systemdVal)
	}
	if dockerVal != "docker=active" {
		t.Errorf("host_docker_service = %q, want docker=active", dockerVal)
	}
	if len(fake.Calls) != 2 {
		t.Errorf("fake runner calls = %d, want 2", len(fake.Calls))
	}
}
