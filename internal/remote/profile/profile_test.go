package profile

import (
	"strings"
	"testing"
)

func TestMinimal_HasExpectedFiles(t *testing.T) {
	p := Minimal()
	if p.Name != "minimal" {
		t.Errorf("Name = %q, want minimal", p.Name)
	}
	if p.SchemaVersion != "0.1" {
		t.Errorf("SchemaVersion = %q, want 0.1", p.SchemaVersion)
	}
	if len(p.Files) == 0 {
		t.Fatal("minimal profile has no files")
	}

	required := []string{"env.sh", "aliases.sh", "bin/dd-path", "bin/dd-ports", "bin/dd-proc", "bin/dd-clean", "tmux.conf"}
	found := make(map[string]bool)
	for _, f := range p.Files {
		found[f.LogicalName] = true
	}
	for _, name := range required {
		if !found[name] {
			t.Errorf("minimal profile missing file %q", name)
		}
	}
}

func TestMinimal_NoSecrets(t *testing.T) {
	p := Minimal()
	for _, f := range p.Files {
		if strings.Contains(f.Content, "PRIVATE") || strings.Contains(f.Content, "SECRET") {
			t.Errorf("file %q may contain secret-like text", f.LogicalName)
		}
	}
}

func TestSubstituteSessionID(t *testing.T) {
	p := Minimal()
	p.SubstituteSessionID("20260516T203500Z_a19f3c")
	for _, f := range p.Files {
		if strings.Contains(f.Content, "__SESSION_ID__") {
			t.Errorf("file %q still contains __SESSION_ID__ placeholder", f.LogicalName)
		}
	}
}
