package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCheckPortsUsesPortEngineOnly(t *testing.T) {
	dir := t.TempDir()

	// Create an env key mismatch (F-ENV-001/F-ENV-002 trigger)
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("PORT_TEST_ENV=3000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run check ports
	stdout, _, code := runBinaryInDir(dir, "check", "ports", ".", "--format", "json")
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}

	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}

	for _, f := range report.Findings {
		if strings.HasPrefix(f.ID, "F-ENV-") {
			t.Errorf("unrelated env finding %s leaked into check ports output", f.ID)
		}
	}
}

func TestCheckEnvDoesNotEmitPortFindings(t *testing.T) {
	dir := t.TempDir()

	// Create a compose file with a port conflict
	compose := `version: '3'
services:
  web1:
    image: nginx
    ports:
      - "8080:80"
  web2:
    image: nginx
    ports:
      - "8080:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, _ := runBinaryInDir(dir, "check", "env", ".", "--format", "json")
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}

	for _, f := range report.Findings {
		if strings.HasPrefix(f.ID, "F-PORT-") {
			t.Errorf("unrelated port finding %s leaked into check env output", f.ID)
		}
	}
}

func TestCheckContainersWithoutGpuDoesNotEmitGpuFindings(t *testing.T) {
	dir := t.TempDir()

	stdout, _, _ := runBinaryInDir(dir, "check", "containers", ".", "--format", "json")
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}

	for _, f := range report.Findings {
		if strings.HasPrefix(f.ID, "F-GPU-") || strings.HasPrefix(f.ID, "F-DOCKER-GPU-") {
			t.Errorf("unrelated GPU finding %s leaked into check containers output", f.ID)
		}
	}
}

func TestCheckGitIncludesPackageManagerFindings(t *testing.T) {
	dir := t.TempDir()

	gitInit := exec.Command("git", "init")
	gitInit.Dir = dir
	if err := gitInit.Run(); err != nil {
		t.Skip("skipping test: git init command failed")
	}

	// Create package manager conflict (e.g. multiple lockfiles)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, _ := runBinaryInDir(dir, "check", "git", ".", "--format", "json")
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}

	hasPM := false
	for _, f := range report.Findings {
		if strings.HasPrefix(f.ID, "F-PM-") {
			hasPM = true
		}
	}
	if !hasPM {
		t.Errorf("expected F-PM- finding in check git output since package manager conflict exists, got: %+v", report.Findings)
	}
}
