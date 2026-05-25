package disk

import (
	"context"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "disk" {
		t.Errorf("Name() = %q, want %q", got, "disk")
	}
}

func TestCollector_Collect(t *testing.T) {
	c := &Collector{Path: "."}
	ctx := context.Background()
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %q, want ok", res.Status)
	}

	// Should have disk evidence
	hasFreeBytes := false
	hasInodeAvailability := false
	for _, ev := range res.Evidence {
		if ev.Source == "host_disk_free_bytes" {
			hasFreeBytes = true
		}
		if ev.Source == "host_disk_inodes_available" {
			hasInodeAvailability = true
		}
	}
	if !hasFreeBytes {
		t.Error("missing host_disk_free_bytes evidence")
	}
	if !hasInodeAvailability {
		t.Error("missing host_disk_inodes_available evidence")
	}
}
