package pathfilter

import (
	"path/filepath"
	"testing"
)

func TestShouldSkipPathWithPatterns_DefaultDependencyAndGeneratedPaths(t *testing.T) {
	root := t.TempDir()
	cases := []string{
		filepath.Join(root, ".venv", "lib", "python3.14", "site-packages", "pkg", "package.json"),
		filepath.Join(root, "node_modules", "pkg", "package.json"),
		filepath.Join(root, "vendor", "pkg", "package.json"),
		filepath.Join(root, "dist", "package.json"),
		filepath.Join(root, ".git", "config"),
	}
	for _, path := range cases {
		if !ShouldSkipPathWithPatterns(root, path, nil) {
			t.Fatalf("expected %s to be skipped", path)
		}
	}
}

func TestShouldSkipPathWithPatterns_AllowsProjectManifests(t *testing.T) {
	root := t.TempDir()
	cases := []string{
		filepath.Join(root, "package.json"),
		filepath.Join(root, "apps", "web", "package.json"),
		filepath.Join(root, "packages", "ui", "package.json"),
	}
	for _, path := range cases {
		if ShouldSkipPathWithPatterns(root, path, nil) {
			t.Fatalf("expected %s to be treated as project evidence", path)
		}
	}
}

func TestShouldSkipPathWithPatterns_ProjectIgnorePattern(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fixtures", "generated", "package.json")
	if !ShouldSkipPathWithPatterns(root, path, []string{"fixtures/generated/**"}) {
		t.Fatalf("expected custom pattern to skip %s", path)
	}
}
