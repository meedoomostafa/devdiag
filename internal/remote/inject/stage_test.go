package inject

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/remote/profile"
)

func TestStage_MinimalProfile(t *testing.T) {
	p := profile.Minimal()
	dir, files, err := Stage(p)
	if err != nil {
		t.Fatalf("Stage error: %v", err)
	}
	defer os.RemoveAll(dir)

	if len(files) == 0 {
		t.Fatal("expected files to be written")
	}

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.IsDir() {
			t.Errorf("%s is a directory, expected file", f)
		}
	}

	// Check that bin files are executable
	for _, pf := range p.Files {
		if filepath.Dir(pf.TargetPath) == "bin" {
			localPath := filepath.Join(dir, pf.TargetPath)
			info, err := os.Stat(localPath)
			if err != nil {
				t.Fatalf("stat %s: %v", localPath, err)
			}
			mode := info.Mode()
			if mode&0111 == 0 {
				t.Errorf("%s is not executable: %o", localPath, mode)
			}
		}
	}
}

func TestStage_ContentSubstitution(t *testing.T) {
	p := profile.Minimal()
	p.SubstituteSessionID("S1")

	dir, _, err := Stage(p)
	if err != nil {
		t.Fatalf("Stage error: %v", err)
	}
	defer os.RemoveAll(dir)

	envPath := filepath.Join(dir, "env.sh")
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env.sh: %v", err)
	}
	if !contains(string(data), "S1") {
		t.Error("env.sh does not contain substituted session ID")
	}
	if contains(string(data), "__SESSION_ID__") {
		t.Error("env.sh still contains __SESSION_ID__ placeholder")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
