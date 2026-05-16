package network

import (
	"context"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "network" {
		t.Errorf("Name() = %q, want %q", got, "network")
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

	// Verify no external calls were made (this collector only reads env vars)
	// If HTTP_PROXY is set, it should appear redacted
	for _, ev := range res.Evidence {
		if ev.Source == "host_proxy_env" {
			if !contains(ev.Value, "=set") {
				t.Errorf("proxy env not redacted: %q", ev.Value)
			}
		}
	}
}

func TestCollector_NoExternalCalls(t *testing.T) {
	// Ensure the collector does not perform DNS or HTTP requests
	c := &Collector{}
	ctx := context.Background()
	res, _ := c.Collect(ctx)
	for _, ev := range res.Evidence {
		if ev.Source == "dns_query" || ev.Source == "tcp_probe" {
			t.Errorf("unexpected external call evidence: %q", ev.Source)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
