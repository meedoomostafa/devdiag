package capsule

import (
	"bytes"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestInspect_ValidCapsule(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{RunID: "test-run-004"}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}

	result, err := InspectFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid=true")
	}
	if len(result.Errors) > 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
	if len(result.FileList) == 0 {
		t.Error("expected non-empty file list")
	}
	if result.FileCount != len(result.FileList) {
		t.Fatalf("file_count = %d, want %d", result.FileCount, len(result.FileList))
	}
	if result.RunID != report.RunID {
		t.Fatalf("run_id = %q, want %q", result.RunID, report.RunID)
	}
	if result.RedactionStatus != "default" {
		t.Fatalf("redaction_status = %q, want default", result.RedactionStatus)
	}
	if len(result.ReviewSummary) == 0 {
		t.Fatal("expected non-empty review summary")
	}
}

func TestInspect_SummaryNoLogs(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{RunID: "test-run-005"}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}

	result, err := InspectFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	summary := result.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if bytes.Contains([]byte(summary), []byte("secret")) {
		t.Error("summary should not contain raw secrets")
	}
}

func TestInspect_CorruptedData(t *testing.T) {
	_, err := InspectFromBytes([]byte("not a valid gzip"))
	if err == nil {
		t.Fatal("expected error for corrupted data")
	}
}
