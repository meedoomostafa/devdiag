package hostruntime

import (
	"context"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "host_runtime" {
		t.Errorf("Name() = %q, want %q", got, "host_runtime")
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

	// Should have evidence for at least one runtime
	if len(res.Evidence) == 0 {
		t.Error("expected some evidence")
	}
}

func TestCollector_MissingBinaryEvidence(t *testing.T) {
	c := &Collector{}
	ctx := context.Background()
	res, _ := c.Collect(ctx)

	// Check that missing binaries produce evidence, not errors
	for _, ev := range res.Evidence {
		if strings.HasSuffix(ev.Source, "_missing") && ev.Value == "true" {
			// missing binary should have corresponding _path evidence
			rt := strings.TrimSuffix(ev.Source, "_missing")
			rt = strings.TrimPrefix(rt, "host_")
			foundPath := false
			for _, ev2 := range res.Evidence {
				if ev2.Source == rt+"_path" || ev2.Source == "host_"+rt+"_path" {
					foundPath = true
					break
				}
			}
			if !foundPath {
				// Path evidence should exist even when missing
				t.Logf("missing binary without path evidence: %s", ev.Source)
			}
		}
	}
}

func TestDetectVersionManager(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/home/user/.nvm/versions/node/v20/bin/node", "nvm"},
		{"/home/user/.asdf/shims/node", "asdf"},
		{"/home/user/.local/share/mise/shims/python", "mise"},
		{"/home/user/.pyenv/shims/python", "pyenv"},
		{"/home/user/.volta/bin/node", "volta"},
		{"/usr/bin/node", ""},
	}
	for _, tt := range tests {
		if got := detectVersionManager(tt.path); got != tt.want {
			t.Errorf("detectVersionManager(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
