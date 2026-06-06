package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestReportRejectsMissingSource(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runBinaryInDir(dir, "report")
	if code == 0 {
		t.Errorf("expected non-zero exit code, got 0")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "exactly one of --latest, --run-id, or --report must be provided") {
		t.Errorf("expected error message about missing source, got: %s", combined)
	}
}

func TestReportRejectsMultipleSources(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runBinaryInDir(dir, "report", "--latest", "--run-id", "run123")
	if code == 0 {
		t.Errorf("expected non-zero exit code, got 0")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "mutually exclusive") {
		t.Errorf("expected error message about mutual exclusivity, got: %s", combined)
	}
}

func TestReportRejectsReportWithPositionalPath(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runBinaryInDir(dir, "report", "--report", "report.json", "some-path")
	if code == 0 {
		t.Errorf("expected non-zero exit code, got 0")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "--report and [path] cannot be combined") {
		t.Errorf("expected error message about combining report flag with path, got: %s", combined)
	}
}

func TestReportRejectsInvalidRunID(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runBinaryInDir(dir, "report", "--run-id", "../invalid-id")
	if code == 0 {
		t.Errorf("expected non-zero exit code, got 0")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "invalid run ID") {
		t.Errorf("expected error message about invalid run ID, got: %s", combined)
	}
}

func TestReportLoadsDirectReportJSON(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-direct-test",
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Title: "Fake Environment Issue", Severity: schema.SeverityHigh},
		},
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	repPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(repPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBinaryInDir(dir, "report", "--report", repPath, "--format", "json")
	if code != 1 { // exit code 1 because findings exist
		t.Errorf("expected exit code 1, got %d. stderr: %s", code, stderr)
	}

	var parsed schema.Report
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("failed to parse JSON stdout: %v, stdout: %s", err, stdout)
	}
	if parsed.RunID != "run-direct-test" {
		t.Errorf("expected RunID run-direct-test, got %s", parsed.RunID)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].ID != "F-ENV-001" {
		t.Errorf("expected finding F-ENV-001, got findings: %+v", parsed.Findings)
	}
}

func TestReportLoadsRunIDReport(t *testing.T) {
	dir := t.TempDir()
	runID := "run12345"
	rep := schema.Report{
		RunID: runID,
		Findings: []schema.Finding{
			{ID: "F-PORT-001", Title: "Fake Port Conflict", Severity: schema.SeverityHigh},
		},
	}

	runsDir := filepath.Join(dir, ".devdiag", "runs", runID)
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runsDir, "report.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBinaryInDir(dir, "report", "--run-id", runID, "--format", "json")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d. stderr: %s", code, stderr)
	}

	var parsed schema.Report
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("failed to parse JSON stdout: %v, stdout: %s", err, stdout)
	}
	if parsed.RunID != runID {
		t.Errorf("expected RunID %s, got %s", runID, parsed.RunID)
	}
}

func TestReportLoadsLatestReport(t *testing.T) {
	dir := t.TempDir()

	// Create older run
	run1 := "run1"
	rep1 := schema.Report{RunID: run1, Findings: []schema.Finding{{ID: "F-ENV-001", Title: "Old Finding"}}}
	runsDir1 := filepath.Join(dir, ".devdiag", "runs", run1)
	if err := os.MkdirAll(runsDir1, 0o755); err != nil {
		t.Fatal(err)
	}
	data1, _ := json.Marshal(rep1)
	if err := os.WriteFile(filepath.Join(runsDir1, "report.json"), data1, 0o644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	// Create newer run
	run2 := "run2"
	rep2 := schema.Report{RunID: run2, Findings: []schema.Finding{{ID: "F-PORT-001", Title: "New Finding", Severity: schema.SeverityHigh}}}
	runsDir2 := filepath.Join(dir, ".devdiag", "runs", run2)
	if err := os.MkdirAll(runsDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	data2, _ := json.Marshal(rep2)
	if err := os.WriteFile(filepath.Join(runsDir2, "report.json"), data2, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBinaryInDir(dir, "report", "--latest", "--format", "json")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d. stderr: %s", code, stderr)
	}

	var parsed schema.Report
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("failed to parse JSON stdout: %v", err)
	}
	if parsed.RunID != run2 {
		t.Errorf("expected latest run %s, got %s", run2, parsed.RunID)
	}
}

func TestReportRendersMarkdown(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-markdown-test",
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Title: "Fake Environment Issue", Severity: schema.SeverityHigh},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	stdout, _, _ := runBinaryInDir(dir, "report", "--report", repPath, "--format", "markdown")
	if !strings.Contains(stdout, "# DevDiag Report") {
		t.Errorf("expected Markdown title, got: %s", stdout)
	}
	if !strings.Contains(stdout, "F-ENV-001") {
		t.Errorf("expected finding ID in Markdown output, got: %s", stdout)
	}
}

func TestReportRendersGitHubAnnotations(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-github-test",
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Title: "Fake Environment Issue", Severity: schema.SeverityHigh},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	stdout, _, _ := runBinaryInDir(dir, "report", "--report", repPath, "--format", "github")
	if !strings.Contains(stdout, "::error title=F-ENV-001::Fake Environment Issue") {
		t.Errorf("expected GitHub annotation formatting, got: %s", stdout)
	}
}

func TestReportRespectsIncludeHidden(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-hidden-test",
		Findings: []schema.Finding{
			{ID: "F-PORT-001", Title: "Medium Severity Finding", Severity: schema.SeverityMedium},
			{ID: "F-ENV-001", Title: "Low Severity Finding", Severity: schema.SeverityLow},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	// Run without --include-hidden
	stdoutDefault, _, _ := runBinaryInDir(dir, "report", "--report", repPath, "--format", "json")
	var parsedDefault schema.Report
	if err := json.Unmarshal([]byte(stdoutDefault), &parsedDefault); err != nil {
		t.Fatal(err)
	}
	if len(parsedDefault.Findings) != 1 || parsedDefault.Findings[0].ID != "F-PORT-001" {
		t.Errorf("expected default run to hide low finding, got findings: %+v", parsedDefault.Findings)
	}

	// Run with --include-hidden
	stdoutHidden, _, _ := runBinaryInDir(dir, "report", "--report", repPath, "--format", "json", "--include-hidden")
	var parsedHidden schema.Report
	if err := json.Unmarshal([]byte(stdoutHidden), &parsedHidden); err != nil {
		t.Fatal(err)
	}
	if len(parsedHidden.Findings) != 2 {
		t.Errorf("expected both findings with --include-hidden, got findings: %+v", parsedHidden.Findings)
	}
}

func TestReportViewCIIncludesDeployOnlyInfo(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-view-ci-test",
		Findings: []schema.Finding{
			{ID: "F-CI-ENV-DEPLOY-INFO", Title: "Deploy-only CI env", Severity: schema.SeverityInfo},
			{ID: "F-CI-ENV-001", Title: "CI local mismatch", Severity: schema.SeverityMedium},
			{ID: "F-ENV-001", Title: "Env mismatch", Severity: schema.SeverityMedium},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	stdout, stderr, code := runBinaryInDir(dir, "report", "--report", repPath, "--format", "json", "--view", "ci", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("report --view ci exit code = %d, want 0; stderr=%s stdout=%s", code, stderr, stdout)
	}
	var parsed schema.Report
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("report --view ci JSON is invalid: %v; stdout=%s", err, stdout)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("report --view ci findings = %d, want 2: %+v", len(parsed.Findings), parsed.Findings)
	}
	for _, finding := range parsed.Findings {
		if !strings.HasPrefix(finding.ID, "F-CI-") {
			t.Fatalf("report --view ci leaked non-CI finding: %+v", finding)
		}
	}
}

func TestReportViewAllIncludesLowInfoWithoutSuppressed(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-view-all-test",
		Collectors: []schema.CollectorResult{
			{
				Name: "config",
				Evidence: []schema.Evidence{
					{Source: "devdiag_noise_suppress_finding", Value: "id=F-SUPPRESSED-001 reason=accepted"},
				},
			},
		},
		Findings: []schema.Finding{
			{ID: "F-LOW-001", Title: "Low", Severity: schema.SeverityLow},
			{ID: "F-RUNTIME-DECL-001", Title: "Runtime declaration", Severity: schema.SeverityInfo},
			{ID: "F-SUPPRESSED-001", Title: "Suppressed", Severity: schema.SeverityMedium},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	stdout, stderr, code := runBinaryInDir(dir, "report", "--report", repPath, "--format", "json", "--view", "all", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("report --view all exit code = %d, want 0; stderr=%s stdout=%s", code, stderr, stdout)
	}
	var parsed schema.Report
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("report --view all JSON is invalid: %v; stdout=%s", err, stdout)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("report --view all findings = %d, want 2: %+v", len(parsed.Findings), parsed.Findings)
	}
	for _, finding := range parsed.Findings {
		if finding.ID == "F-SUPPRESSED-001" {
			t.Fatal("report --view all should not bypass configured suppressions without --include-hidden")
		}
	}
}

func TestReportRespectsFailSeverity(t *testing.T) {
	dir := t.TempDir()
	rep := schema.Report{
		RunID: "run-fail-test",
		Findings: []schema.Finding{
			{ID: "F-PORT-001", Title: "Medium Severity Finding", Severity: schema.SeverityMedium},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	// fail-severity high -> exit code 0 because medium is below threshold
	_, _, codeHigh := runBinaryInDir(dir, "report", "--report", repPath, "--fail-severity", "high")
	if codeHigh != 0 {
		t.Errorf("expected exit code 0 for fail-severity=high, got %d", codeHigh)
	}

	// fail-severity medium -> exit code 1 because medium meets threshold
	_, _, codeMedium := runBinaryInDir(dir, "report", "--report", repPath, "--fail-severity", "medium")
	if codeMedium != 1 {
		t.Errorf("expected exit code 1 for fail-severity=medium, got %d", codeMedium)
	}
}

func TestReportLatestCannotRecoverUnsavedHiddenFindings(t *testing.T) {
	dir := t.TempDir()
	// Report saved without the hidden finding (already omitted/filtered before saving)
	rep := schema.Report{
		RunID: "run-unsaved-test",
		Findings: []schema.Finding{
			{ID: "F-PORT-001", Title: "Medium Severity Finding", Severity: schema.SeverityMedium},
		},
	}
	data, _ := json.Marshal(rep)
	repPath := filepath.Join(dir, "report.json")
	_ = os.WriteFile(repPath, data, 0o644)

	// Using --include-hidden on this report should still output only F-PORT-001
	stdout, _, _ := runBinaryInDir(dir, "report", "--report", repPath, "--format", "json", "--include-hidden")
	var parsed schema.Report
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].ID != "F-PORT-001" {
		t.Errorf("expected only findings present in JSON to render, got: %+v", parsed.Findings)
	}
}
