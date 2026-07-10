package pathfilter

import (
	"os"
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

func TestClassifyPath_EnvDirOnlySkippedWhenVirtualEnv(t *testing.T) {
	root := t.TempDir()

	// Plain env/ config directory: must be treated as project evidence.
	configDir := filepath.Join(root, "env")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(configDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("key: value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ShouldSkipPathWithPatterns(root, configFile, nil) {
		t.Fatalf("expected non-venv env/ contents %s to be project evidence", configFile)
	}
	if got := ClassifyPath(root, configFile); got != PathProject {
		t.Fatalf("ClassifyPath(env/config.yaml) = %s, want project", got)
	}

	// env/ that is a Python virtualenv (pyvenv.cfg marker): skip as dependency.
	venvRoot := t.TempDir()
	venvDir := filepath.Join(venvRoot, "env")
	if err := os.MkdirAll(venvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvDir, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	venvFile := filepath.Join(venvDir, "lib", "site-packages", "pkg", "package.json")
	if !ShouldSkipPathWithPatterns(venvRoot, venvFile, nil) {
		t.Fatalf("expected venv env/ contents %s to be skipped", venvFile)
	}

	// env/ with bin/activate marker (no pyvenv.cfg): also a venv.
	activateRoot := t.TempDir()
	activateBin := filepath.Join(activateRoot, "env", "bin")
	if err := os.MkdirAll(activateBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activateBin, "activate"), []byte("# venv\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	activateFile := filepath.Join(activateRoot, "env", "lib", "pkg", "package.json")
	if !ShouldSkipPathWithPatterns(activateRoot, activateFile, nil) {
		t.Fatalf("expected venv env/ contents %s to be skipped", activateFile)
	}
}

func TestShouldSkipDir_EnvNameAloneNotSkipped(t *testing.T) {
	// Name-only checks cannot verify venv markers, so plain env/ must not be
	// skipped on name alone; venv detection happens in path classification.
	for _, name := range []string{"env", "ENV"} {
		if ShouldSkipDir(name) {
			t.Fatalf("ShouldSkipDir(%q) = true, want false", name)
		}
	}
	if !ShouldSkipDir(".venv") {
		t.Fatal("ShouldSkipDir(.venv) = false, want true")
	}
}

func TestShouldSkipPathWithPatterns_ProjectIgnorePattern(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fixtures", "generated", "package.json")
	if !ShouldSkipPathWithPatterns(root, path, []string{"fixtures/generated/**"}) {
		t.Fatalf("expected custom pattern to skip %s", path)
	}
}

func TestMatchGlob_GlobstarMatchesZeroSegments(t *testing.T) {
	// Standard globstar semantics: a/**/b matches a/b as well as a/x/b.
	cases := []struct {
		pattern string
		rel     string
		want    bool
	}{
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "ab", false},
		{"fixtures/**/package.json", "fixtures/package.json", true},
		{"fixtures/**/package.json", "fixtures/deep/nested/package.json", true},
		{"**/site-packages/**", "lib/site-packages/pkg/mod.py", true},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.rel); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.rel, got, tc.want)
		}
	}
}
