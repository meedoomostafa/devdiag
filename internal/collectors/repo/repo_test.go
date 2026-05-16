package repo

import (
	"context"
	"os"
	"path/filepath"
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

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
