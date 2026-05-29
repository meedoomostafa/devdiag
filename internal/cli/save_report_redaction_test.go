package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSaveReport_RedactsPersistedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devdiag-save-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	secret := "secret-token-12345"
	trigger := "--token=" + secret

	rulePackDir := filepath.Join(tmpDir, "rules")
	os.MkdirAll(rulePackDir, 0755)

	regoFile := filepath.Join(rulePackDir, "leak.rego")
	regoContent := `package devdiag.m1
findings contains f if {
    f := {
        "id": "F-LEAK-001",
        "severity": "high",
        "title": "Leak of ` + trigger + `",
        "symptom": "Found ` + trigger + ` in output"
    }
}`
	if err := os.WriteFile(regoFile, []byte(regoContent), 0644); err != nil {
		t.Fatal(err)
	}

	yamlFile := filepath.Join(rulePackDir, "rulepack.yaml")
	yamlContent := `schema_version: "1"
id: "leak-test"
version: "1"
engine: "rego"
entrypoint: "data.devdiag.m1.findings"
policy_files: ["leak.rego"]
rules:
  - id: "F-LEAK-001"
    severity: "high"`
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Run with redaction (default)
	stdout, stderr, code := runBinaryInDir(tmpDir, "scan", ".", "--save-report", "--rule-pack", yamlFile)
	if code != 1 { // Expected 1 because of high severity finding
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
	}

	runsDir := filepath.Join(tmpDir, ".devdiag", "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil || len(entries) == 0 {
		t.Fatal("no report saved")
	}
	reportPath := filepath.Join(runsDir, entries[0].Name(), "report.json")

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), secret) {
		t.Errorf("LEAK STILL PRESENT: report.json contains unredacted secret %q", secret)
	}

	// 2. Run with redaction OFF
	os.RemoveAll(filepath.Join(tmpDir, ".devdiag"))
	stdout, stderr, code = runBinaryInDir(tmpDir, "scan", ".", "--save-report", "--rule-pack", yamlFile, "--redact", "off")

	entries, _ = os.ReadDir(runsDir)
	reportPath = filepath.Join(runsDir, entries[0].Name(), "report.json")
	data, _ = os.ReadFile(reportPath)

	if !strings.Contains(string(data), secret) {
		t.Error("Redact off failed: report.json does NOT contain raw secret")
	}
	if !strings.Contains(stderr, "redaction is disabled") {
		t.Error("Warning missing when redaction is disabled")
	}
}
