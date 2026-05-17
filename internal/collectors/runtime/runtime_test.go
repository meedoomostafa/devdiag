package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Nvmrc(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".nvmrc"), []byte("22\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var found bool
	for _, ev := range res.Evidence {
		if ev.Source == ".nvmrc" && ev.Value == "node 22" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected .nvmrc evidence, got: %v", res.Evidence)
	}
}

func TestCollector_GoMod(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example\n\ngo 1.23\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var found bool
	for _, ev := range res.Evidence {
		if ev.Source == "go.mod" && ev.Value == "go 1.23" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected go.mod evidence, got: %v", res.Evidence)
	}
}

func TestCollector_PackageManager(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"packageManager":"pnpm@9.0.0"}`), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var found bool
	for _, ev := range res.Evidence {
		if ev.Source == "package.json" && ev.Value == "packageManager: pnpm@9.0.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected packageManager evidence, got: %v", res.Evidence)
	}
}

func TestCollector_GlobalJSONDotnetSDK(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "global.json"), []byte(`{"sdk":{"version":"8.0.204"}}`), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var found bool
	for _, ev := range res.Evidence {
		if ev.Source == "global.json" && ev.Value == "dotnet 8.0.204" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected global.json dotnet evidence, got: %v", res.Evidence)
	}
}

func TestCollector_NoRuntimeFiles(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(res.Evidence) != 0 {
		t.Errorf("expected no evidence, got %d", len(res.Evidence))
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %s, want ok", res.Status)
	}
}
