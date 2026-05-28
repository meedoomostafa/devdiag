package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/redact"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// TestInspectPersistenceLogic verifies that the CLI-level persistence logic
// for the inspect command correctly redacts the report before saving.
// This tests the logic in runInspect without requiring a full TTY/Bubble Tea run.
func TestInspectPersistenceLogic_Redacts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devdiag-inspect-persist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	secret := "secret-token-12345"
	trigger := "--token=" + secret

	// 1. Create a report with a secret
	report := &schema.Report{
		RunID: "test-run-123",
		Repo:  schema.RepoInfo{Root: tmpDir},
		Findings: []schema.Finding{
			{
				ID:    "F-TEST-001",
				Title: "Title with " + trigger,
			},
		},
	}

	// 2. Mock the persistence logic used in runInspect:
	// if inspectSaveReport {
	//     if m, ok := finalModel.(tui.Model); ok && m.Report() != nil {
	//         redacted := buildRedactEngine().RedactReport(m.Report())
	//         persistReport(redacted)
	//     }
	// }
	
	// We'll use the default redact engine (which has default rules enabled)
	engine := redact.NewEngine(redact.LevelDefault)
	redacted := engine.RedactReport(report)
	
	err = persistReport(tmpDir, redacted)
	if err != nil {
		t.Fatalf("persistReport failed: %v", err)
	}

	// 3. Verify the file on disk
	reportPath := filepath.Join(tmpDir, ".devdiag", "runs", report.RunID, "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), secret) {
		t.Errorf("LEAK IN INSPECT PERSISTENCE: report.json contains unredacted secret %q", secret)
	} else {
		t.Log("Inspect persistence logic correctly redacted the report")
	}
}

// TestInspectPersistenceLogic_RedactOff verifies that persistence preserves raw data when off.
func TestInspectPersistenceLogic_RedactOff(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devdiag-inspect-persist-off-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	secret := "secret-token-12345"
	trigger := "--token=" + secret

	report := &schema.Report{
		RunID: "test-run-off",
		Repo:  schema.RepoInfo{Root: tmpDir},
		Findings: []schema.Finding{
			{
				ID:    "F-TEST-002",
				Title: "Title with " + trigger,
			},
		},
	}

	// Mock runInspect logic with LevelOff
	engine := redact.NewEngine(redact.LevelOff)
	redacted := engine.RedactReport(report)
	
	err = persistReport(tmpDir, redacted)
	if err != nil {
		t.Fatal(err)
	}

	reportPath := filepath.Join(tmpDir, ".devdiag", "runs", report.RunID, "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), secret) {
		t.Error("Inspect persistence logic REDACTED even though redaction was OFF")
	}
}
