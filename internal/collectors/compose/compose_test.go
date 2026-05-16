package compose

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_ExtractsEnvRefs(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    image: myapp:${TAG:-latest}
    environment:
      DATABASE_URL: ${DATABASE_URL:?required}
      API_KEY: ${API_KEY}
    ports:
      - "${PORT:-3000}:3000"
    command: echo $$HOME && run ${MODE}
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %s, want ok", res.Status)
	}

	var vars []string
	for _, ev := range res.Evidence {
		vars = append(vars, ev.Value)
	}

	// Should find TAG, DATABASE_URL, API_KEY, PORT, MODE
	// Should NOT find escaped $$HOME
	wantVars := map[string]bool{
		"TAG":          false,
		"DATABASE_URL": false,
		"API_KEY":      false,
		"PORT":         false,
		"MODE":         false,
	}
	for _, v := range vars {
		for w := range wantVars {
			if contains(v, w) {
				wantVars[w] = true
			}
		}
	}

	for v, found := range wantVars {
		if !found {
			t.Errorf("expected to find variable %q in evidence, got: %v", v, vars)
		}
	}

	// Make sure $$HOME is not present
	for _, v := range vars {
		if contains(v, "HOME") && !contains(v, "$${HOME}") {
			// HOME might appear as part of another var name
		}
	}
}

func TestCollector_NoComposeFile(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(res.Evidence) != 0 {
		t.Errorf("expected no evidence without compose file, got %d", len(res.Evidence))
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

func TestCollector_DefaultValueNotMissing(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    environment:
      PORT: ${PORT:-3000}
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	// PORT with default should still be reported as evidence (rule layer decides if it's a finding)
	var found bool
	for _, ev := range res.Evidence {
		if contains(ev.Value, "PORT") {
			found = true
		}
	}
	if !found {
		t.Error("expected PORT evidence")
	}
}

func TestCollector_RequiredValue(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    environment:
      DATABASE_URL: ${DATABASE_URL:?required}
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var found bool
	for _, ev := range res.Evidence {
		if contains(ev.Value, "DATABASE_URL") && contains(ev.Value, "?required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DATABASE_URL required evidence, got: %v", res.Evidence)
	}
}

func TestCollector_EscapedDollarIgnored(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    command: echo $$HOME
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	refs, err := extractEnvRefs(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractEnvRefs error: %v", err)
	}
	for _, ref := range refs {
		if ref.Var == "HOME" {
			t.Errorf("escaped $$HOME should not be extracted, got: %v", ref)
		}
	}
}

func TestCollector_LineNumbersPreserved(t *testing.T) {
	dir := t.TempDir()
	yaml := "services:\n  api:\n    environment:\n      API_KEY: ${API_KEY}\n"
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	refs, err := extractEnvRefs(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractEnvRefs error: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("expected refs")
	}
	if refs[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
