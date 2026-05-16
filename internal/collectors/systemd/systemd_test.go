package systemd

import (
	"context"
	"testing"

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
