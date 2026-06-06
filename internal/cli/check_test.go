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

func repoFixturePath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	return path
}

func assertFindingIDsHavePrefixes(t *testing.T, report schema.Report, allowed ...string) {
	t.Helper()
	for _, finding := range report.Findings {
		var ok bool
		for _, prefix := range allowed {
			if strings.HasPrefix(finding.ID, prefix) {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("finding %s leaked outside allowed prefixes %v; findings=%+v", finding.ID, allowed, report.Findings)
		}
	}
}

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

func TestCheckPorts_UsesEnvEvidenceForComposeRefs(t *testing.T) {
	fixture := repoFixturePath(t, "nexuq-like")
	stdout, stderr, code := runBinary("check", "ports", fixture, "--format", "json", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("check ports fixture exit code = %d, want 0; stderr=%s stdout=%s", code, stderr, stdout)
	}

	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("check ports stdout is not valid JSON: %v; stdout=%s", err, stdout)
	}
	assertFindingIDsHavePrefixes(t, report, "F-PORT-")
	for _, finding := range report.Findings {
		if strings.Contains(finding.Title, "NEXUQ_POSTGRES_PASSWORD") ||
			strings.Contains(finding.Title, "NEXUQ_REDIS_PASSWORD") ||
			strings.Contains(finding.Title, "NEXUQ_WEBHOOK_SECRET") {
			t.Fatalf("compose env reference that exists in .env leaked into check ports finding: %+v", finding)
		}
	}
}

func TestCheckPorts_DoesNotEmitCrossDomainFindings(t *testing.T) {
	fixture := repoFixturePath(t, "nexuq-like")
	stdout, stderr, _ := runBinary("check", "ports", fixture, "--format", "json", "--fail-severity", "off")
	if stdout == "" {
		t.Fatalf("check ports produced no JSON output; stderr=%s", stderr)
	}
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("check ports stdout is not valid JSON: %v; stdout=%s", err, stdout)
	}
	assertFindingIDsHavePrefixes(t, report, "F-PORT-")
}

func TestCheckDomainCommandsDoNotLeakCrossDomainFindings(t *testing.T) {
	fixture := repoFixturePath(t, "nexuq-like")
	tests := []struct {
		name    string
		args    []string
		allowed []string
	}{
		{name: "env", args: []string{"check", "env", fixture}, allowed: []string{"F-ENV-"}},
		{name: "ci", args: []string{"check", "ci", fixture}, allowed: []string{"F-CI-"}},
		{name: "ports", args: []string{"check", "ports", fixture}, allowed: []string{"F-PORT-"}},
		{name: "containers", args: []string{"check", "containers", fixture}, allowed: []string{"F-CONTAINER-", "F-DOCKER-", "F-PODMAN-", "F-COMPOSE-"}},
		{name: "runtimes", args: []string{"check", "runtimes", fixture}, allowed: []string{"F-RUNTIME-"}},
		{name: "git", args: []string{"check", "git", fixture}, allowed: []string{"F-GIT-", "F-PM-"}},
		{name: "services", args: []string{"check", "services", fixture}, allowed: []string{"F-SVC-"}},
		{name: "network", args: []string{"check", "network", fixture}, allowed: []string{"F-NET-"}},
		{name: "filesystem", args: []string{"check", "filesystem", fixture}, allowed: []string{"F-DISK-", "F-FS-", "F-PERM-"}},
		{name: "security", args: []string{"check", "security", fixture}, allowed: []string{"F-SEC-"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(append([]string{}, tt.args...), "--format", "json", "--fail-severity", "off")
			stdout, stderr, _ := runBinary(args...)
			if stdout == "" {
				t.Fatalf("%s produced no JSON output; stderr=%s", strings.Join(args, " "), stderr)
			}
			var report schema.Report
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("%s stdout is not valid JSON: %v; stdout=%s", strings.Join(args, " "), err, stdout)
			}
			assertFindingIDsHavePrefixes(t, report, tt.allowed...)
		})
	}
}

func TestEnvConfigRequiredWhitelist(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("REQUIRED_KEY=\nOPTIONAL_BY_WHITELIST=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devdiag.yaml"), []byte("env:\n  required:\n    - REQUIRED_KEY\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBinaryInDir(dir, "check", "env", ".", "--format", "json", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("check env exit code = %d, want 0; stderr=%s stdout=%s", code, stderr, stdout)
	}
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("check env stdout is not valid JSON: %v; stdout=%s", err, stdout)
	}
	assertReportFindingEvidenceValue(t, report, "F-ENV-001", "REQUIRED_KEY")
	assertReportFindingEvidenceAbsent(t, report, "F-ENV-001", "OPTIONAL_BY_WHITELIST")
	assertReportFindingEvidenceValue(t, report, "F-ENV-001-OPTIONAL", "OPTIONAL_BY_WHITELIST")
}

func TestEnvConfigMissingDotEnvWithAllKeysOptional(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("OPTIONAL_A=\nOPTIONAL_B=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devdiag.yaml"), []byte("env:\n  optional:\n    - OPTIONAL_A\n    - OPTIONAL_B\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBinaryInDir(dir, "check", "env", ".", "--format", "json", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("check env exit code = %d, want 0; stderr=%s stdout=%s", code, stderr, stdout)
	}
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("check env stdout is not valid JSON: %v; stdout=%s", err, stdout)
	}
	for _, finding := range report.Findings {
		if finding.ID == "F-ENV-001" {
			t.Fatalf("missing .env with only optional keys should not emit actionable F-ENV-001: %+v", finding)
		}
	}
	assertReportFinding(t, report, "F-ENV-001-OPTIONAL")
}

func TestCheckCI_ClassifiesDeploymentOnlySecrets(t *testing.T) {
	fixture := repoFixturePath(t, "nexuq-like")
	stdout, stderr, code := runBinary("check", "ci", fixture, "--format", "json", "--fail-severity", "off", "--include-hidden")
	if code != 0 {
		t.Fatalf("check ci exit code = %d, want 0; stderr=%s stdout=%s", code, stderr, stdout)
	}
	var report schema.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("check ci stdout is not valid JSON: %v; stdout=%s", err, stdout)
	}
	for _, key := range []string{"CONFIRM_DEPLOY", "RELEASE_SHA", "OCI_SSH_PRIVATE_KEY", "OCI_HOST"} {
		assertReportFindingEvidenceAbsent(t, report, "F-CI-ENV-001", key)
		assertReportFindingEvidenceValue(t, report, "F-CI-ENV-DEPLOY-INFO", key)
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
