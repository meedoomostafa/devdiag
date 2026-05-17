package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollector_DetectsGoModule(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var foundGo bool
	for _, ev := range res.Evidence {
		if ev.Source == "go.mod" {
			foundGo = true
		}
	}
	if !foundGo {
		t.Error("expected go.mod evidence")
	}
}

func TestCollector_DetectsMultipleLockfiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(""), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var foundLockfiles bool
	for _, ev := range res.Evidence {
		if ev.Source == "lockfiles" {
			foundLockfiles = true
			if !contains(ev.Value, "package-lock.json") || !contains(ev.Value, "yarn.lock") {
				t.Errorf("lockfiles evidence = %q", ev.Value)
			}
		}
	}
	if !foundLockfiles {
		t.Error("expected lockfiles evidence")
	}
}

func TestCollector_DetectsLocalCISimulators(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".actrc"), []byte("-P ubuntu-latest=node:20\n"), 0644)
	os.WriteFile(filepath.Join(dir, "wrkflw.toml"), []byte("[defaults]\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	found := map[string]bool{}
	for _, ev := range res.Evidence {
		if ev.Source == "local_ci_simulator" {
			found[ev.Value] = true
		}
	}
	for _, want := range []string{"act", "wrkflw"} {
		if !found[want] {
			t.Errorf("expected local_ci_simulator=%s in %v", want, res.Evidence)
		}
	}
}

func TestCollector_ExtractsLocalCommandEvidence(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
  "packageManager": "pnpm@9.0.0",
  "scripts": {
    "test": "vitest run",
    "lint": "eslint ."
  }
}`), 0644)
	os.WriteFile(filepath.Join(dir, "Makefile"), []byte("test:\n\tgo test ./...\n"), 0644)
	os.WriteFile(filepath.Join(dir, "Taskfile.yml"), []byte("tasks:\n  build:\n    cmds:\n      - go build ./...\n"), 0644)
	os.WriteFile(filepath.Join(dir, "justfile"), []byte("fmt:\n\tgofmt -w .\n"), 0644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("Run `pnpm test` before pushing.\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	checks := map[string]string{
		"repo_package_manager":             "pnpm@9.0.0",
		"repo_command__package_json__test": "pnpm test",
		"repo_command__package_json__lint": "pnpm lint",
		"repo_command__makefile__test":     "make test",
		"repo_command__taskfile__build":    "task build",
		"repo_command__justfile__fmt":      "just fmt",
		"repo_command__readme__pnpm_test":  "pnpm test",
	}
	for source, value := range checks {
		var found bool
		for _, ev := range res.Evidence {
			if ev.Source == source && ev.Value == value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected evidence %s=%s in %v", source, value, res.Evidence)
		}
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
