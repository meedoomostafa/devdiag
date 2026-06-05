package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestCollector_NestedPackageJSONRuntime(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "docs-site")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{"engines":{"node":">=24"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "ignored"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "ignored", "package.json"), []byte(`{"engines":{"node":">=1"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	venvPackageDir := filepath.Join(dir, ".venv", "lib", "python3.14", "site-packages", "playwright", "driver", "package")
	if err := os.MkdirAll(venvPackageDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvPackageDir, "package.json"), []byte(`{"engines":{"node":">=1"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	assertRuntimeEvidence(t, res.Evidence, "docs-site/package.json", `engines: "node": ">=24"`)
	for _, ev := range res.Evidence {
		if strings.Contains(ev.Source, "node_modules") || strings.Contains(ev.Source, ".venv") || strings.Contains(ev.Source, "site-packages") {
			t.Fatalf("dependency package.json should not be collected: %v", res.Evidence)
		}
	}
}

func TestCollector_NestedPackageJSONRuntime_RespectsConfiguredIgnorePaths(t *testing.T) {
	dir := t.TempDir()
	generatedDir := filepath.Join(dir, "fixtures", "generated")
	if err := os.MkdirAll(generatedDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generatedDir, "package.json"), []byte(`{"engines":{"node":">=1"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(dir, "apps", "web")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{"engines":{"node":">=24"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devdiag.yaml"), []byte("noise:\n  ignore_paths:\n    - fixtures/generated/**\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	assertRuntimeEvidence(t, res.Evidence, "apps/web/package.json", `engines: "node": ">=24"`)
	for _, ev := range res.Evidence {
		if strings.Contains(ev.Source, "fixtures/generated") {
			t.Fatalf("configured ignored package.json should not be collected: %v", res.Evidence)
		}
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

func assertRuntimeEvidence(t *testing.T, evidence []schema.Evidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			return
		}
	}
	t.Fatalf("expected %s=%q evidence, got: %v", source, value, evidence)
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
