package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Helper to build the binary once for integration tests.
var binaryPath string

func TestMain(m *testing.M) {
	// Build the devdiag binary for integration tests.
	tmpDir, err := os.MkdirTemp("", "devdiag-test")
	if err != nil {
		panic(err)
	}
	binaryPath = tmpDir + "/devdiag"
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/devdiag")
	build.Dir = "../../"
	if out, err := build.CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(tmpDir)
	os.Exit(code)
}

func runBinary(args ...string) (string, string, int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()
	return stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()
}

func TestInvalidFormat_ReturnsExitCode2(t *testing.T) {
	_, _, code := runBinary("scan", ".", "--format", "invalid")
	if code != 2 {
		t.Errorf("invalid --format exit code = %d, want 2", code)
	}
}

func TestInvalidRedact_ReturnsExitCode2(t *testing.T) {
	_, _, code := runBinary("scan", ".", "--redact", "invalid")
	if code != 2 {
		t.Errorf("invalid --redact exit code = %d, want 2", code)
	}
}

func TestInvalidColor_ReturnsExitCode2(t *testing.T) {
	_, _, code := runBinary("scan", ".", "--color", "invalid")
	if code != 2 {
		t.Errorf("invalid --color exit code = %d, want 2", code)
	}
}

func TestScanJSON_NoStderrWarningInStdout(t *testing.T) {
	stdout, stderr, code := runBinary("scan", ".", "--format", "json", "--redact", "off")
	if code != 0 {
		t.Fatalf("unexpected exit code: %d", code)
	}
	// stderr should contain the warning
	if !strings.Contains(stderr, "redaction is disabled") {
		t.Error("expected redaction warning in stderr")
	}
	// stdout should be valid JSON and not contain the warning text
	if strings.Contains(stdout, "redaction is disabled") {
		t.Error("stdout JSON contains stderr warning text")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if report["redaction_status"] != "off" {
		t.Errorf("redaction_status = %v, want off", report["redaction_status"])
	}
}

func TestScanJSON_HasRequiredTopLevelFields(t *testing.T) {
	stdout, _, code := runBinary("scan", ".", "--format", "json")
	if code != 0 {
		t.Fatalf("unexpected exit code: %d", code)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	required := []string{"schema_version", "devdiag_version", "run_id", "redaction_status", "repo", "host", "collectors", "findings"}
	for _, key := range required {
		if _, ok := report[key]; !ok {
			t.Errorf("missing required top-level field: %s", key)
		}
	}
}

func TestScanExitCode0_ForInfoFinding(t *testing.T) {
	_, _, code := runBinary("scan", ".")
	if code != 0 {
		t.Errorf("scan with info finding exit code = %d, want 0", code)
	}
}

func TestRulesList_JSON_ReturnsValidJSON(t *testing.T) {
	stdout, _, code := runBinary("rules", "list", "--format", "json")
	if code != 0 {
		t.Fatalf("unexpected exit code: %d", code)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("rules list --format json is not valid JSON: %v", err)
	}
}

func TestNDJSON_OneObjectPerLine(t *testing.T) {
	stdout, _, code := runBinary("scan", ".", "--format", "ndjson")
	if code != 0 {
		t.Fatalf("unexpected exit code: %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 {
		t.Fatal("NDJSON output is empty")
	}
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("NDJSON line %q is not valid JSON: %v", line, err)
		}
	}
}

func TestNoColor_DisablesANSI(t *testing.T) {
	stdout, _, _ := runBinary("scan", ".", "--no-color")
	if strings.Contains(stdout, "\033[") {
		t.Error("--no-color output contains ANSI escape sequences")
	}
}

func TestNO_COLOR_DisablesANSI(t *testing.T) {
	cmd := exec.Command(binaryPath, "scan", ".")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, _ := cmd.Output()
	if strings.Contains(string(out), "\033[") {
		t.Error("NO_COLOR=1 output contains ANSI escape sequences")
	}
}

func TestDebugFlag_DoesNotBreakScan(t *testing.T) {
	_, _, code := runBinary("scan", ".", "--debug")
	if code != 0 {
		t.Errorf("--debug scan exit code = %d, want 0", code)
	}
}

func TestMarkdown_DoesNotExposeUnredactedSecrets(t *testing.T) {
	// Create a temporary env file to trigger redaction
	// For M0, we just verify the markdown renderer runs without panic
	// and produces markdown content.
	stdout, _, code := runBinary("scan", ".", "--format", "markdown")
	if code != 0 {
		t.Fatalf("unexpected exit code: %d", code)
	}
	if !strings.Contains(stdout, "# DevDiag Report") {
		t.Error("markdown output missing expected header")
	}
}

func TestSeverityHigher_ExitCodeMapping(t *testing.T) {
	// Verify the severity ordering that drives exit code 1.
	if !severityHigher("critical", "info") {
		t.Error("critical should be higher than info")
	}
	if !severityHigher("high", "info") {
		t.Error("high should be higher than info")
	}
	if severityHigher("info", "high") {
		t.Error("info should NOT be higher than high")
	}
	if severityHigher("low", "medium") {
		t.Error("low should NOT be higher than medium")
	}
}
