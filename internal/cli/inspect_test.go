package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/tui"
)

func TestInspectRejectsMutuallyExclusiveLatestRunIDReport(t *testing.T) {
	// Combination 1: latest and runID
	_, err := resolveInspectReport(nil, true, "run-123", "")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got %v", err)
	}

	// Combination 2: runID and reportPath
	_, err = resolveInspectReport(nil, false, "run-123", "report.json")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got %v", err)
	}

	// Combination 3: latest and reportPath
	_, err = resolveInspectReport(nil, true, "", "report.json")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got %v", err)
	}
}

func TestInspectReportRejectsPositionalPath(t *testing.T) {
	_, err := resolveInspectReport([]string{"some-path"}, false, "", "report.json")
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("expected combination error, got %v", err)
	}
}

func TestInspectRejectsInvalidRunID(t *testing.T) {
	_, err := resolveInspectReport(nil, false, "../invalid", "")
	if err == nil || !strings.Contains(err.Error(), "invalid run ID") {
		t.Errorf("expected invalid run ID error, got %v", err)
	}
}

func TestInspectLoadsReportFile(t *testing.T) {
	tmpDir := t.TempDir()
	rep := schema.Report{
		RunID: "run-report-direct",
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Title: "Fake Env"},
		},
	}
	repPath := filepath.Join(tmpDir, "rep.json")
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := resolveInspectReport(nil, false, "", repPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loaded.mode != tui.ModeReport {
		t.Errorf("expected ModeReport, got %v", loaded.mode)
	}
	if loaded.sourceName != repPath {
		t.Errorf("expected sourceName = %q, got %q", repPath, loaded.sourceName)
	}
	if loaded.report.RunID != "run-report-direct" {
		t.Errorf("expected loaded report RunID = run-report-direct, got %q", loaded.report.RunID)
	}
}

func TestInspectLoadsRunIDReport(t *testing.T) {
	tmpDir := t.TempDir()
	runID := "run123"
	rep := schema.Report{
		RunID: runID,
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Title: "Fake Env"},
		},
	}

	// Create .devdiag/runs/run123/report.json under tmpDir
	runsDir := filepath.Join(tmpDir, ".devdiag", "runs", runID)
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runsDir, "report.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := resolveInspectReport([]string{tmpDir}, false, runID, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loaded.mode != tui.ModeRun {
		t.Errorf("expected ModeRun, got %v", loaded.mode)
	}
	if loaded.sourceName != runID {
		t.Errorf("expected sourceName = %q, got %q", runID, loaded.sourceName)
	}
	if loaded.report.RunID != runID {
		t.Errorf("expected loaded report RunID = %q, got %q", runID, loaded.report.RunID)
	}
}

func TestInspectLatestLoadsLatestReport(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create run1 (older)
	run1 := "run1"
	rep1 := schema.Report{RunID: run1}
	runsDir1 := filepath.Join(tmpDir, ".devdiag", "runs", run1)
	if err := os.MkdirAll(runsDir1, 0o755); err != nil {
		t.Fatal(err)
	}
	data1, _ := json.Marshal(rep1)
	if err := os.WriteFile(filepath.Join(runsDir1, "report.json"), data1, 0o644); err != nil {
		t.Fatal(err)
	}

	// Sleep slightly to guarantee mod time difference
	time.Sleep(100 * time.Millisecond)

	// 2. Create run2 (newer)
	run2 := "run2"
	rep2 := schema.Report{RunID: run2}
	runsDir2 := filepath.Join(tmpDir, ".devdiag", "runs", run2)
	if err := os.MkdirAll(runsDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	data2, _ := json.Marshal(rep2)
	if err := os.WriteFile(filepath.Join(runsDir2, "report.json"), data2, 0o644); err != nil {
		t.Fatal(err)
	}

	// Resolve latest
	loaded, err := resolveInspectReport([]string{tmpDir}, true, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loaded.mode != tui.ModeRun {
		t.Errorf("expected ModeRun, got %v", loaded.mode)
	}
	if loaded.sourceName != run2 {
		t.Errorf("expected sourceName = %q (run2), got %q", run2, loaded.sourceName)
	}
}
