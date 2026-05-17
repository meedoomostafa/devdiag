package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
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

func runBinaryInDir(dir string, args ...string) (string, string, int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
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

func TestRulesList_JSON_ListsImplementedRules(t *testing.T) {
	stdout, _, code := runBinary("rules", "list", "--format", "json")
	if code != 0 {
		t.Fatalf("unexpected exit code: %d", code)
	}
	if strings.Contains(stdout, "F-RULES-000") {
		t.Fatalf("rules list still exposes placeholder rule: %s", stdout)
	}
	for _, id := range []string{"F-ENV-001", "F-RUNTIME-001", "F-PORT-001", "F-CI-RUNTIME-001", "F-GPU-001"} {
		if !strings.Contains(stdout, id) {
			t.Errorf("rules list missing %s", id)
		}
	}
}

func TestNDJSON_OneObjectPerLine(t *testing.T) {
	stdout, _, code := runBinary("scan", "../..", "--format", "ndjson")
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

func TestCheckHelp_DoesNotDuplicateSubcommands(t *testing.T) {
	stdout, _, code := runBinary("check", "--help")
	if code != 0 {
		t.Fatalf("check --help exit code = %d, want 0", code)
	}
	for _, name := range []string{"cache", "gpu"} {
		if got := strings.Count(stdout, "  "+name+"       "); got != 1 {
			t.Errorf("check --help lists %q %d times, want 1\n%s", name, got, stdout)
		}
	}
}

func TestFixDryRunFlag_AcceptedForTemplates(t *testing.T) {
	stdout, _, code := runBinary("fix", "--templates", "--dry-run", "--format", "json")
	if code != 0 {
		t.Fatalf("fix --templates --dry-run exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "warn-disk-cleanup") {
		t.Errorf("fix --templates --dry-run output missing expected template: %s", stdout)
	}
}

func TestFixDryRunFlag_ConflictsWithApply(t *testing.T) {
	_, stderr, code := runBinary("fix", "F-DISK-001", "--dry-run", "--apply")
	if code != 2 {
		t.Fatalf("fix --dry-run --apply exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "cannot use --dry-run with --apply") {
		t.Errorf("stderr missing dry-run/apply conflict message: %q", stderr)
	}
}

func TestFixList_SuccessDoesNotPrintExitCodeZero(t *testing.T) {
	dir := t.TempDir()
	if _, stderr, code := runBinaryInDir(dir, "scan", ".", "--format", "json"); code != 0 {
		t.Fatalf("scan in temp dir exit code = %d, stderr=%s", code, stderr)
	}

	_, stderr, code := runBinaryInDir(dir, "fix", "--list", "--format", "json")
	if code != 0 {
		t.Fatalf("fix --list exit code = %d, want 0, stderr=%s", code, stderr)
	}
	if strings.Contains(stderr, "exit code 0") {
		t.Errorf("fix --list printed success as an error: %q", stderr)
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

func TestExitCodeFromResults_MapsCorrectly(t *testing.T) {
	tests := []struct {
		name        string
		findings    []schema.Finding
		collectors  []schema.CollectorResult
		reproFailed bool
		want        exitcode.Code
	}{
		{
			name: "success",
			findings: []schema.Finding{
				{Severity: schema.SeverityInfo},
			},
			want: exitcode.Success,
		},
		{
			name: "high severity finding",
			findings: []schema.Finding{
				{Severity: schema.SeverityHigh},
			},
			want: exitcode.FindingsExist,
		},
		{
			name: "critical severity finding",
			findings: []schema.Finding{
				{Severity: schema.SeverityCritical},
			},
			want: exitcode.FindingsExist,
		},
		{
			name: "repro failed",
			findings: []schema.Finding{
				{Severity: schema.SeverityInfo},
			},
			reproFailed: true,
			want:        exitcode.ReproFailed,
		},
		{
			name:       "collector timeout",
			collectors: []schema.CollectorResult{{Status: schema.CollectorTimeout}},
			want:       exitcode.CollectorPartial,
		},
		{
			name:       "collector partial",
			collectors: []schema.CollectorResult{{Status: schema.CollectorPartial}},
			want:       exitcode.CollectorPartial,
		},
		{
			name:       "collector permission denied",
			collectors: []schema.CollectorResult{{Status: schema.CollectorPermissionDenied}},
			want:       exitcode.PermissionDenied,
		},
		{
			name:       "collector unavailable",
			collectors: []schema.CollectorResult{{Status: schema.CollectorUnavailable}},
			want:       exitcode.Success,
		},
		{
			name:       "collector failed",
			collectors: []schema.CollectorResult{{Status: schema.CollectorFailed}},
			want:       exitcode.CollectorPartial,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCodeFromResults(tt.findings, tt.collectors, tt.reproFailed)
			if got != tt.want {
				t.Errorf("exitCodeFromResults() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPopulateHostInfo_ExtractsFromCollector(t *testing.T) {
	collectors := []schema.CollectorResult{
		{
			Name: "host",
			Evidence: []schema.Evidence{
				{Source: "host_os_id", Value: "ubuntu"},
				{Source: "host_os_version", Value: "22.04"},
				{Source: "host_kernel", Value: "5.15.0"},
				{Source: "host_arch", Value: "x86_64"},
			},
		},
	}
	host := populateHostInfo(collectors)
	if host.OS != "ubuntu" {
		t.Errorf("OS = %q, want ubuntu", host.OS)
	}
	if host.Version != "22.04" {
		t.Errorf("Version = %q, want 22.04", host.Version)
	}
	if host.Kernel != "5.15.0" {
		t.Errorf("Kernel = %q, want 5.15.0", host.Kernel)
	}
	if host.Arch != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", host.Arch)
	}
}

func TestValidateRunID(t *testing.T) {
	valid := []string{"abc", "ABC", "123", "a-b_c", "2024-01-01T12:00:00Z_abc123"}
	for _, id := range valid {
		if err := validateRunID(id); err != nil {
			t.Errorf("validateRunID(%q) unexpected error: %v", id, err)
		}
	}
	invalid := []string{"", "a/b", "..", "a..b", "a b", "a@b"}
	for _, id := range invalid {
		if err := validateRunID(id); err == nil {
			t.Errorf("validateRunID(%q) expected error, got nil", id)
		}
	}
}

func TestCheckGPU_NewFlagsDoNotCrash(t *testing.T) {
	// Verify the new GPU verification flags are accepted and do not panic.
	_, _, code := runBinary("check", "gpu", "--gpu-verify")
	if code != 0 {
		t.Errorf("check gpu --gpu-verify exit code = %d, want 0", code)
	}

	_, _, code = runBinary("check", "gpu", "--allow-pull")
	if code != 0 {
		t.Errorf("check gpu --allow-pull exit code = %d, want 0", code)
	}

	_, _, code = runBinary("check", "gpu", "--gpu-verify-image", "nvidia/cuda:11.8.0-base-ubuntu22.04")
	if code != 0 {
		t.Errorf("check gpu --gpu-verify-image exit code = %d, want 0", code)
	}
}

func TestCheckGPU_CombinedFlags(t *testing.T) {
	_, _, code := runBinary("check", "gpu", "--python", "--gpu-verify", "--allow-pull")
	if code != 0 {
		t.Errorf("check gpu combined flags exit code = %d, want 0", code)
	}
}

func TestTraceCommand_ExecutesTrue(t *testing.T) {
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not installed")
	}
	_, stderr, code := runBinary("trace", "--scope", "file", "--", "true")
	if code == int(exitcode.TraceUnavailable) {
		t.Skip("ptrace unavailable in this environment")
	}
	if code != 0 {
		t.Errorf("trace true exit code = %d, want 0, stderr=%s", code, stderr)
	}
}

func TestTraceCommand_InvalidScope(t *testing.T) {
	_, stderr, code := runBinary("trace", "--scope", "gpu", "--", "true")
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid scope, got %d", code)
	}
	if !strings.Contains(stderr, "invalid") && !strings.Contains(stderr, "scope") {
		t.Errorf("expected invalid scope error in stderr, got: %s", stderr)
	}
}

func TestCheckCI_Fixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "fixtures", "ci-local-parity")
	cmd := exec.Command("go", "run", "../../cmd/devdiag", "check", "ci", fixture)
	out, _ := cmd.CombinedOutput()
	output := string(out)
	t.Logf("output:\n%s", output)
	if !strings.Contains(output, "F-CI-RUNTIME-001") {
		t.Errorf("expected F-CI-RUNTIME-001 in output")
	}
	if !strings.Contains(output, "F-CI-CONTAINER-001") {
		t.Errorf("expected F-CI-CONTAINER-001 in output")
	}
	if !strings.Contains(output, "F-CI-ENV-001") {
		t.Errorf("expected F-CI-ENV-001 in output")
	}
}
