package ci

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_ExtractsRunCommands(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: npm install
      - name: Test
        run: npm test
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %s, want ok", res.Status)
	}
	if len(res.Evidence) != 2 {
		t.Errorf("expected 2 commands, got %d: %v", len(res.Evidence), res.Evidence)
	}

	var hasInstall, hasTest bool
	for _, ev := range res.Evidence {
		if ev.Value == "npm install" {
			hasInstall = true
		}
		if ev.Value == "npm test" {
			hasTest = true
		}
	}
	if !hasInstall {
		t.Error("expected 'npm install' command")
	}
	if !hasTest {
		t.Error("expected 'npm test' command")
	}
}

func TestCollector_NoWorkflows(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(res.Evidence) != 0 {
		t.Errorf("expected no evidence, got %d", len(res.Evidence))
	}
}
