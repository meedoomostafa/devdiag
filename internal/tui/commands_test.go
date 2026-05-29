package tui

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// knownCommands is the set of real devdiag commands that may appear as hints.
var knownCommands = map[string]bool{
	"devdiag scan":             true,
	"devdiag scan . --verbose": true,
	"devdiag check ci":         true,
	"devdiag check containers": true,
	"devdiag check security":   true,
	"devdiag check gpu":        true,
	"devdiag check cache":      true,
	"devdiag check ports":      true,
	"devdiag fix":              true,
}

func TestDeriveCommandHints_OnlyRealCommands(t *testing.T) {
	domains := []string{"ci", "containers", "security", "gpu", "cache", "network", "general"}
	for _, domain := range domains {
		f := InspectFinding{
			Finding: schema.Finding{ID: "F-TEST-001", Fixes: []schema.Fix{{Title: "Fix it"}}},
			Domain:  domain,
		}
		hints := deriveCommandHints(f)
		if len(hints) == 0 {
			t.Errorf("domain %s: expected at least one hint", domain)
			continue
		}
		for _, h := range hints {
			found := false
			for known := range knownCommands {
				if strings.HasPrefix(h.Command, known) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("domain %s: unknown command %q", domain, h.Command)
			}
		}
	}
}

func TestDeriveCommandHints_FixDryRun(t *testing.T) {
	f := InspectFinding{
		Finding: schema.Finding{
			ID:    "F-ENV-001",
			Fixes: []schema.Fix{{Title: "Rotate secret"}},
		},
		Domain:       "env",
		MutationRisk: "high",
	}
	hints := deriveCommandHints(f)
	var hasFix bool
	for _, h := range hints {
		if h.Kind == "fix" {
			hasFix = true
			if !strings.HasPrefix(h.Command, "devdiag fix") {
				t.Errorf("fix hint should start with 'devdiag fix', got %q", h.Command)
			}
			if h.MutationRisk != "high" {
				t.Errorf("fix hint mutation risk = %q, want high", h.MutationRisk)
			}
		}
	}
	if !hasFix {
		t.Error("expected a fix hint when Fixes are present")
	}
}

func TestDeriveCommandHints_NoFixWhenEmpty(t *testing.T) {
	f := InspectFinding{
		Finding: schema.Finding{ID: "F-ENV-001"},
		Domain:  "env",
	}
	hints := deriveCommandHints(f)
	for _, h := range hints {
		if h.Kind == "fix" {
			t.Error("expected no fix hint when Fixes are empty")
		}
	}
}

func TestDeriveTarget(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"F-CI-001", "CI pipeline"},
		{"F-RUNTIME-001", "local runtime"},
		{"F-ENV-001", "environment"},
		{"F-SECURITY-001", "security posture"},
		{"F-CONTAINER-001", "container environment"},
		{"F-GPU-001", "GPU/ML stack"},
		{"F-HOST-001", "host system"},
		{"F-UNKNOWN-001", "project"},
	}
	for _, tt := range tests {
		f := schema.Finding{ID: tt.id}
		got := deriveTarget(f)
		if got != tt.want {
			t.Errorf("deriveTarget(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestDeriveRelatedResources(t *testing.T) {
	f := InspectFinding{
		Finding: schema.Finding{
			Evidence: []schema.Evidence{
				{Source: "url_docs", Value: "https://example.com/docs"},
				{Source: "config_file", Value: "/etc/app.conf"},
			},
		},
	}
	resources := deriveRelatedResources(f)
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
}
