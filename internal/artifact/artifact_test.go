package artifact

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArtifactHelpers(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "project")
	err := os.MkdirAll(filepath.Join(base, ".devdiag", "runs", "run123"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Test RunsDir
	expectedRuns := filepath.Join(base, ".devdiag", "runs")
	if got := RunsDir(base); got != expectedRuns {
		t.Errorf("RunsDir() = %v, want %v", got, expectedRuns)
	}

	// Test RunDir
	expectedRun := filepath.Join(expectedRuns, "run123")
	if got := RunDir(base, "run123"); got != expectedRun {
		t.Errorf("RunDir() = %v, want %v", got, expectedRun)
	}

	// Test DiscoverBase from subdirectory
	sub := filepath.Join(base, "src", "cmd")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	gotBase, err := DiscoverBase(sub)
	if err != nil {
		t.Errorf("DiscoverBase() error = %v", err)
	}
	if gotBase != base {
		t.Errorf("DiscoverBase() = %v, want %v", gotBase, base)
	}

	// Test DiscoverBase failure
	_, err = DiscoverBase(tmp)
	if err != ErrNoRunsFound {
		t.Errorf("DiscoverBase(tmp) error = %v, want ErrNoRunsFound", err)
	}
}

func TestWriteFilePrivate(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "subdir", "file.txt")
	data := []byte("secret")
	if err := WriteFilePrivate(path, data); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("FilePerm = %o, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Join(tmp, "subdir"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("DirPerm = %o, want 0700", perm)
	}
}

func TestFindLatestRunID(t *testing.T) {
	tmp := t.TempDir()
	runs := filepath.Join(tmp, ".devdiag", "runs")
	if err := os.MkdirAll(filepath.Join(runs, "run1"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runs, "run2"), 0700); err != nil {
		t.Fatal(err)
	}

	// Manually set mod time to ensure run2 is latest
	now := time.Now()
	if err := os.Chtimes(filepath.Join(runs, "run2"), now, now); err != nil {
		t.Fatal(err)
	}

	got, err := FindLatestRunID(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got != "run2" {
		t.Errorf("FindLatestRunID() = %v, want run2", got)
	}

	// Test symlink
	if err := os.Symlink("run1", filepath.Join(runs, "latest")); err != nil {
		t.Fatal(err)
	}
	got, err = FindLatestRunID(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got != "run1" {
		t.Errorf("FindLatestRunID() with symlink = %v, want run1", got)
	}

	// Test unsafe symlink
	os.Remove(filepath.Join(runs, "latest"))
	if err := os.Symlink("../evil", filepath.Join(runs, "latest")); err != nil {
		t.Fatal(err)
	}
	_, err = FindLatestRunID(tmp)
	if err == nil {
		t.Error("FindLatestRunID() with traversal symlink expected error, got nil")
	}

	os.Remove(filepath.Join(runs, "latest"))
	if err := os.Symlink("/tmp/evil", filepath.Join(runs, "latest")); err != nil {
		t.Fatal(err)
	}
	_, err = FindLatestRunID(tmp)
	if err == nil {
		t.Error("FindLatestRunID() with absolute external symlink expected error, got nil")
	}

	os.Remove(filepath.Join(runs, "latest"))
	if err := os.Symlink("run/child", filepath.Join(runs, "latest")); err != nil {
		t.Fatal(err)
	}
	_, err = FindLatestRunID(tmp)
	if err == nil {
		t.Error("FindLatestRunID() with nested symlink expected error, got nil")
	}

	// Test latest -> latest (loop or self-reference)
	os.Remove(filepath.Join(runs, "latest"))
	if err := os.Symlink("latest", filepath.Join(runs, "latest")); err != nil {
		t.Fatal(err)
	}
	_, err = FindLatestRunID(tmp)
	if err == nil {
		t.Error("FindLatestRunID() with latest -> latest expected error, got nil")
	}

	// Test latest -> run.with.dot
	if err := os.MkdirAll(filepath.Join(runs, "run.with.dot"), 0700); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(runs, "latest"))
	if err := os.Symlink("run.with.dot", filepath.Join(runs, "latest")); err != nil {
		t.Fatal(err)
	}
	_, err = FindLatestRunID(tmp)
	if err == nil {
		t.Error("FindLatestRunID() with dots in symlink target expected error, got nil")
	}
}
