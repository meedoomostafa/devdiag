package podman

import (
	"context"
	"strings"
	"testing"

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
