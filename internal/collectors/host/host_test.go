package host

import (
	"context"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "host" {
		t.Errorf("Name() = %q, want %q", got, "host")
	}
}

func TestCollector_Collect(t *testing.T) {
	c := &Collector{}
	ctx := context.Background()
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %q, want ok", res.Status)
	}

	// Should have at least host_goos and host_arch evidence
	hasGoos := false
	hasArch := false
	for _, ev := range res.Evidence {
		if ev.Source == "host_goos" {
			hasGoos = true
		}
		if ev.Source == "host_arch" {
			hasArch = true
		}
	}
	if !hasGoos {
		t.Error("missing host_goos evidence")
	}
	if !hasArch {
		t.Error("missing host_arch evidence")
	}
}

func TestParseOSRelease(t *testing.T) {
	id, version := parseOSRelease("/etc/os-release")
	// On Linux, this may succeed or fail; just verify no panic
	t.Logf("os-release: id=%q version=%q", id, version)
}
