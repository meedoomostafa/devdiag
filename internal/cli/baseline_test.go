package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/baseline"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// setupBaselineTestProject creates a minimal saved report under a temp dir.
func setupBaselineTestProject(t *testing.T, findings []schema.Finding) string {
	t.Helper()
	dir := t.TempDir()

	report := schema.Report{
		SchemaVersion:   schema.SchemaVersion,
		DevDiagVersion:  "test",
		RunID:           "2026-06-06T12-00-00Z_abcd",
		RedactionStatus: "default",
		Repo:            schema.RepoInfo{Root: dir},
		Collectors:      []schema.CollectorResult{{Name: "host", Status: schema.CollectorOK}},
		Findings:        findings,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	runsDir := artifact.RunDir(dir, report.RunID)
	if err := os.MkdirAll(runsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	reportPath := filepath.Join(runsDir, "report.json")
	if err := os.WriteFile(reportPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Create latest symlink
	latestLink := artifact.LatestLink(dir)
	os.Remove(latestLink)
	if err := os.Symlink(report.RunID, latestLink); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return dir
}

func TestBaselineCreateFromLatestReport(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
		{ID: "F-HIGH-001", Severity: schema.SeverityHigh, Title: "High issue"},
	})

	stdout, stderr, code := runBinary("baseline", "create", dir, "--reason", "accepted for v1.0")
	if code != 0 {
		t.Fatalf("exit=%d; stdout=%s; stderr=%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "Created baseline with 2 entries") {
		t.Fatalf("unexpected output: %s", stdout)
	}

	// Verify baseline file exists and is valid
	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(b.Entries))
	}
	if b.SchemaVersion != baseline.SchemaVersion {
		t.Fatalf("schema = %q, want %q", b.SchemaVersion, baseline.SchemaVersion)
	}
}

func TestBaselineCreateRefusesEmptyReason(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})

	_, _, code := runBinary("baseline", "create", dir)
	if code == 0 {
		t.Fatal("expected non-zero exit for missing --reason")
	}
}

func TestBaselineCreateRefusesOverwriteWithoutForce(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})

	// Create baseline first time
	_, _, code := runBinary("baseline", "create", dir, "--reason", "first")
	if code != 0 {
		t.Fatalf("first create failed with exit %d", code)
	}

	// Try again without --force
	_, _, code = runBinary("baseline", "create", dir, "--reason", "second")
	if code == 0 {
		t.Fatal("expected non-zero exit without --force")
	}
}

func TestBaselineCreateWithForceOverwrites(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})

	_, _, code := runBinary("baseline", "create", dir, "--reason", "first")
	if code != 0 {
		t.Fatalf("first create failed with exit %d", code)
	}

	_, _, code = runBinary("baseline", "create", dir, "--reason", "overwritten", "--force")
	if code != 0 {
		t.Fatalf("force overwrite failed with exit %d", code)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.Entries[0].Reason != "overwritten" {
		t.Fatalf("reason = %q, want overwritten", b.Entries[0].Reason)
	}
}

func TestBaselineCreateWithExpiry(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})

	_, _, code := runBinary("baseline", "create", dir, "--reason", "temporary", "--expires", "30d")
	if code != 0 {
		t.Fatalf("create with expiry failed with exit %d", code)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.Entries[0].ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	if b.Entries[0].ExpiresAt.Before(time.Now()) {
		t.Fatal("ExpiresAt should be in the future")
	}
}

func TestBaselineCreateWithMinSeverity(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-LOW-001", Severity: schema.SeverityLow, Title: "Low"},
		{ID: "F-MED-001", Severity: schema.SeverityMedium, Title: "Medium"},
		{ID: "F-HIGH-001", Severity: schema.SeverityHigh, Title: "High"},
	})

	_, _, code := runBinary("baseline", "create", dir, "--reason", "high only", "--min-severity", "high")
	if code != 0 {
		t.Fatalf("create with min-severity failed with exit %d", code)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (high only)", len(b.Entries))
	}
	if b.Entries[0].ID != "F-HIGH-001" {
		t.Fatalf("entry = %q, want F-HIGH-001", b.Entries[0].ID)
	}
}

func TestBaselineCreateWithRunID(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})

	_, stderr, code := runBinary("baseline", "create", dir, "--reason", "run test", "--run-id", "2026-06-06T12-00-00Z_abcd")
	if code != 0 {
		t.Fatalf("create with --run-id failed with exit %d; stderr=%s", code, stderr)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(b.Entries))
	}
}

func TestBaselineCreateNoSavedReport(t *testing.T) {
	dir := t.TempDir()

	_, _, code := runBinary("baseline", "create", dir, "--reason", "test")
	if code == 0 {
		t.Fatal("expected non-zero exit when no saved report exists")
	}
}

func TestBaselineListEmptyBaseline(t *testing.T) {
	dir := t.TempDir()

	stdout, _, code := runBinary("baseline", "list", dir)
	if code != 0 {
		t.Fatalf("list failed with exit %d", code)
	}
	if !strings.Contains(stdout, "Total: 0 entries") {
		t.Fatalf("unexpected output for empty baseline: %s", stdout)
	}
}

func TestBaselineListWithEntries(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted", CreatedAt: now},
			{ID: "F-EXPIRED-001", Reason: "old", CreatedAt: now, ExpiresAt: &past},
			{ID: "F-ACTIVE-001", Reason: "current", CreatedAt: now, ExpiresAt: &future},
		},
	}
	if err := baseline.Save(baseline.DefaultPath(dir), b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, _, code := runBinary("baseline", "list", dir)
	if code != 0 {
		t.Fatalf("list failed with exit %d", code)
	}
	if !strings.Contains(stdout, "3 entries") {
		t.Fatalf("expected 3 entries in output: %s", stdout)
	}
	if !strings.Contains(stdout, "2 active") {
		t.Fatalf("expected 2 active in output: %s", stdout)
	}
	if !strings.Contains(stdout, "1 expired") {
		t.Fatalf("expected 1 expired in output: %s", stdout)
	}
}

func TestReportReportModeDoesNotImplicitlyDiscoverBaseline(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})
	now := time.Now().UTC()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "baselined", CreatedAt: now},
		},
	}
	if err := baseline.Save(baseline.DefaultPath(dir), b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	// Use --report with direct file path — baseline should NOT be discovered.
	reportFilePath := filepath.Join(artifact.RunDir(dir, "2026-06-06T12-00-00Z_abcd"), "report.json")
	stdout, stderr, code := runBinary("report", "--report", reportFilePath, "--format", "json")
	if code != 0 {
		t.Fatalf("report --report failed with exit %d; stderr=%s", code, stderr)
	}

	// The finding should still be visible (baseline not applied).
	if !strings.Contains(stdout, "F-ENV-001") {
		t.Fatalf("expected F-ENV-001 to be visible (no baseline applied), got: %s", stdout)
	}
}

func TestReportReportModeWithExplicitBaseline(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
		{ID: "F-HIGH-001", Severity: schema.SeverityHigh, Title: "High issue"},
	})
	now := time.Now().UTC()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "baselined", CreatedAt: now},
		},
	}
	baselinePath := baseline.DefaultPath(dir)
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	reportFilePath := filepath.Join(artifact.RunDir(dir, "2026-06-06T12-00-00Z_abcd"), "report.json")
	stdout, stderr, code := runBinary("report", "--report", reportFilePath, "--baseline", baselinePath, "--format", "json", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("report --report --baseline failed with exit %d; stderr=%s", code, stderr)
	}

	if strings.Contains(stdout, "F-ENV-001") {
		t.Fatalf("expected F-ENV-001 to be hidden by baseline, got: %s", stdout)
	}
	if !strings.Contains(stdout, "F-HIGH-001") {
		t.Fatalf("expected F-HIGH-001 to remain visible, got: %s", stdout)
	}
}

func TestBaselineCreateRefusesWhitespaceReason(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
	})

	_, _, code := runBinary("baseline", "create", dir, "--reason", "   ")
	if code == 0 {
		t.Fatal("expected non-zero exit for whitespace-only --reason")
	}
}

func TestBaselineValidateMissingFileReturnsInvalidInput(t *testing.T) {
	dir := t.TempDir()

	stdout, stderr, code := runBinary("baseline", "validate", dir)
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing baseline validation, got stdout=%s; stderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "baseline not found") {
		t.Fatalf("expected error message to contain 'baseline not found', got: %s", stderr)
	}
}

func TestBaselineValidateInvalidFile(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("invalid yaml { ["), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, stderr, code := runBinary("baseline", "validate", dir)
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid baseline validation")
	}
	if !strings.Contains(stderr, "validate baseline") {
		t.Fatalf("expected error message to contain 'validate baseline', got: %s", stderr)
	}
}

func TestBaselineValidateValidFile(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	now := time.Now().UTC()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted", CreatedAt: now},
		},
	}
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, stderr, code := runBinary("baseline", "validate", dir)
	if code != 0 {
		t.Fatalf("expected code 0, got %d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "is valid") {
		t.Fatalf("expected stdout to mention 'is valid', got: %s", stdout)
	}
}

func TestBaselinePathOutput(t *testing.T) {
	dir := t.TempDir()
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	expectedPath := baseline.DefaultPath(absDir)

	stdout, stderr, code := runBinary("baseline", "path", dir)
	if code != 0 {
		t.Fatalf("expected code 0, got %d; stderr=%s", code, stderr)
	}
	gotPath := strings.TrimSpace(stdout)
	if gotPath != expectedPath {
		t.Fatalf("got path = %q, want %q", gotPath, expectedPath)
	}
}

func TestBaselineStatusMissing(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runBinary("baseline", "status", dir)
	if code != 0 {
		t.Fatalf("expected code 0, got %d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "Baseline: Not Found") {
		t.Fatalf("expected 'Baseline: Not Found', got: %s", stdout)
	}
}

func TestBaselineStatusInvalid(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("invalid yaml { ["), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, stderr, code := runBinary("baseline", "status", dir)
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid baseline status")
	}
	if !strings.Contains(stderr, "load baseline") {
		t.Fatalf("expected error message to contain 'load baseline', got: %s", stderr)
	}
}

func TestBaselineStatusValid(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted", CreatedAt: now},
			{ID: "F-EXPIRED", Reason: "old", CreatedAt: now, ExpiresAt: &past},
		},
	}
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, stderr, code := runBinary("baseline", "status", dir)
	if code != 0 {
		t.Fatalf("expected code 0, got %d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "Status: Valid") {
		t.Fatalf("expected 'Status: Valid', got: %s", stdout)
	}
	if !strings.Contains(stdout, "Active Entries: 1") {
		t.Fatalf("expected 'Active Entries: 1', got: %s", stdout)
	}
	if !strings.Contains(stdout, "Expired Entries: 1") {
		t.Fatalf("expected 'Expired Entries: 1', got: %s", stdout)
	}
}

func TestBaselineListFormattingTableColumns(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	now := time.Now().UTC()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted", CreatedAt: now, CreatedBy: "medo"},
		},
	}
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, _, code := runBinary("baseline", "list", dir)
	if code != 0 {
		t.Fatalf("list failed with exit %d", code)
	}

	// Verify headers and fields are present
	for _, expected := range []string{"FINDING ID", "STATUS", "EXPIRES AT", "CREATED BY", "CREATED AT", "REASON", "F-ENV-001", "active", "medo", "accepted"} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("expected list output to contain %q, got:\n%s", expected, stdout)
		}
	}
}

func TestBaselineCreateWithFingerprintWritesFingerprint(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue", Symptom: "symptom 1"},
	})

	stdout, stderr, code := runBinary("baseline", "create", dir, "--reason", "accepted specific", "--fingerprint")
	if code != 0 {
		t.Fatalf("exit=%d; stdout=%s; stderr=%s", code, stdout, stderr)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(b.Entries))
	}
	if b.Entries[0].Fingerprint == "" {
		t.Fatal("expected entry to have a fingerprint")
	}
}

func TestBaselineListShowsMatchMode(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	now := time.Now().UTC()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted 1", CreatedAt: now, CreatedBy: "medo"},
			{ID: "F-ENV-002", Reason: "accepted 2", CreatedAt: now, CreatedBy: "medo", Fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
	}
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, _, code := runBinary("baseline", "list", dir)
	if code != 0 {
		t.Fatalf("list failed with exit %d", code)
	}

	for _, expected := range []string{"MATCH", "id", "fingerprint"} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("expected list output to contain %q, got:\n%s", expected, stdout)
		}
	}
}

func TestReportWithFingerprintBaselineHidesOnlyMatchingSymptom(t *testing.T) {
	dir := setupBaselineTestProject(t, []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue", Symptom: "symptom 1"},
		{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue", Symptom: "symptom 2"},
	})

	now := time.Now().UTC()
	fp := baseline.Fingerprint(schema.Finding{ID: "F-ENV-001", Symptom: "symptom 1"})
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "accepted symptom 1", CreatedAt: now},
		},
	}
	baselinePath := baseline.DefaultPath(dir)
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	reportFilePath := filepath.Join(artifact.RunDir(dir, "2026-06-06T12-00-00Z_abcd"), "report.json")
	stdout, stderr, code := runBinary("report", "--report", reportFilePath, "--baseline", baselinePath, "--format", "json", "--fail-severity", "off")
	if code != 0 {
		t.Fatalf("report failed with exit %d; stderr=%s", code, stderr)
	}

	var rep schema.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("invalid json: %v; stdout=%s", err, stdout)
	}

	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 visible finding, got %d", len(rep.Findings))
	}
	if rep.Findings[0].Symptom != "symptom 2" {
		t.Fatalf("expected finding with symptom 2 to be visible, got symptom: %q", rep.Findings[0].Symptom)
	}
}

func TestBaselinePruneMissingBaselineExitsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := runBinary("baseline", "prune", dir)
	if code == 0 {
		t.Fatal("expected non-zero exit for missing baseline pruning")
	}
	if !strings.Contains(stderr, "baseline not found") {
		t.Fatalf("expected 'baseline not found' in stderr, got: %s", stderr)
	}
}

func TestBaselinePruneInvalidBaselineExitsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("invalid yaml { ["), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, stderr, code := runBinary("baseline", "prune", dir)
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid baseline pruning")
	}
	if !strings.Contains(stderr, "load baseline") {
		t.Fatalf("expected 'load baseline' in stderr, got: %s", stderr)
	}
}

func TestBaselinePruneValidBaselinePrunesExpiredAndSaves(t *testing.T) {
	dir := t.TempDir()
	baselinePath := baseline.DefaultPath(dir)
	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-EXPIRED", Reason: "old", CreatedAt: now, ExpiresAt: &past},
			{ID: "F-ACTIVE", Reason: "current", CreatedAt: now, ExpiresAt: &future},
		},
	}
	if err := baseline.Save(baselinePath, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, stderr, code := runBinary("baseline", "prune", dir)
	if code != 0 {
		t.Fatalf("expected code 0, got %d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "Pruned 1 expired entries. 1 active entries remaining.") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}

	loaded, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].ID != "F-ACTIVE" {
		t.Fatalf("expected F-ACTIVE to remain, got %s", loaded.Entries[0].ID)
	}
}

func TestBaselineAddCreatesMissingBaselineFile(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runBinary("baseline", "add", "F-ENV-001", dir, "--reason", "added manually")
	if code != 0 {
		t.Fatalf("expected code 0, got %d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "Added entry for F-ENV-001 (match: id) to baseline.") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(b.Entries))
	}
	if b.Entries[0].ID != "F-ENV-001" || b.Entries[0].Reason != "added manually" {
		t.Fatalf("unexpected entry: %+v", b.Entries[0])
	}
}

func TestBaselineAddInvalidFingerprintExitsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := runBinary("baseline", "add", "F-ENV-001", dir, "--reason", "test", "--fingerprint", "invalid-fp")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid fingerprint add")
	}
	if !strings.Contains(stderr, "invalid --fingerprint") {
		t.Fatalf("expected 'invalid --fingerprint' in stderr, got: %s", stderr)
	}
}

func TestBaselineAddSameIDTwiceUpdates(t *testing.T) {
	dir := t.TempDir()
	_, _, code := runBinary("baseline", "add", "F-ENV-001", dir, "--reason", "first reason")
	if code != 0 {
		t.Fatalf("first add failed with exit %d", code)
	}

	stdout, _, code := runBinary("baseline", "add", "F-ENV-001", dir, "--reason", "second reason")
	if code != 0 {
		t.Fatalf("second add failed with exit %d", code)
	}
	if !strings.Contains(stdout, "Updated entry for F-ENV-001 (match: id) in baseline.") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(b.Entries))
	}
	if b.Entries[0].Reason != "second reason" {
		t.Fatalf("expected reason to be updated, got %q", b.Entries[0].Reason)
	}
}

func TestBaselineAddSameIDWithDifferentFingerprintsCreatesSeparate(t *testing.T) {
	dir := t.TempDir()
	fp1 := "aaa" + strings.Repeat("0", 61)
	fp2 := "bbb" + strings.Repeat("0", 61)

	_, _, code := runBinary("baseline", "add", "F-ENV-001", dir, "--reason", "first", "--fingerprint", fp1)
	if code != 0 {
		t.Fatalf("add fp1 failed: %d", code)
	}

	_, _, code = runBinary("baseline", "add", "F-ENV-001", dir, "--reason", "second", "--fingerprint", fp2)
	if code != 0 {
		t.Fatalf("add fp2 failed: %d", code)
	}

	b, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(b.Entries))
	}
}

func TestBaselineRemoveIDOnlyDoesNotRemoveFingerprint(t *testing.T) {
	dir := t.TempDir()
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "broad", CreatedAt: time.Now()},
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "specific", CreatedAt: time.Now()},
		},
	}
	if err := baseline.Save(baseline.DefaultPath(dir), b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, _, code := runBinary("baseline", "remove", "F-ENV-001", dir)
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(stdout, "Removed entry for F-ENV-001 (match: id) from baseline.") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}

	loaded, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry to remain, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].Fingerprint != fp {
		t.Fatalf("expected fingerprint entry to remain, got %q", loaded.Entries[0].Fingerprint)
	}
}

func TestBaselineRemoveFingerprintDoesNotRemoveIDOnly(t *testing.T) {
	dir := t.TempDir()
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "broad", CreatedAt: time.Now()},
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "specific", CreatedAt: time.Now()},
		},
	}
	if err := baseline.Save(baseline.DefaultPath(dir), b); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, _, code := runBinary("baseline", "remove", "F-ENV-001", dir, "--fingerprint", fp)
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(stdout, "Removed entry for F-ENV-001 (match: fingerprint) from baseline.") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}

	loaded, err := baseline.Load(baseline.DefaultPath(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry to remain, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].Fingerprint != "" {
		t.Fatalf("expected ID-only entry to remain, got %q", loaded.Entries[0].Fingerprint)
	}
}
