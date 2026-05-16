package capsule

import (
	"bytes"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/repro"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestBuilder_CreatesValidTgz(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{
		SchemaVersion:   "1.0",
		DevDiagVersion:  "0.1.0",
		RunID:           "test-run-001",
		RedactionStatus: "default",
	}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

func TestBuilder_IncludesManifest(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{
		SchemaVersion:   "1.0",
		DevDiagVersion:  "0.1.0",
		RunID:           "test-run-002",
		RedactionStatus: "default",
	}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}

	result, err := InspectFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if result.Manifest == nil {
		t.Fatal("expected manifest")
	}
	if result.Manifest.RunID != "test-run-002" {
		t.Errorf("expected run_id test-run-002, got %s", result.Manifest.RunID)
	}
	if result.Manifest.CapsuleSchemaVersion == "" {
		t.Error("expected capsule_schema_version")
	}
}

func TestBuilder_IncludesRepro(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{
		RunID: "test-run-003",
	}
	r := &repro.ReproResult{Command: "echo", ExitCode: 0}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, r); err != nil {
		t.Fatalf("Build error: %v", err)
	}

	result, err := InspectFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	var hasRepro bool
	for _, f := range result.FileList {
		if f == "repro.json" {
			hasRepro = true
		}
	}
	if !hasRepro {
		t.Error("expected repro.json in capsule")
	}
}

func TestIsSafePath(t *testing.T) {
	tests := []struct {
		path string
		safe bool
	}{
		{"report.json", true},
		{"snapshot/repo.json", true},
		{"../escape", false},
		{"/absolute", false},
		{"safe.txt", true},
		{"foo..bar/file.json", true},
	}
	for _, tc := range tests {
		if got := isSafePath(tc.path); got != tc.safe {
			t.Errorf("isSafePath(%q) = %v, want %v", tc.path, got, tc.safe)
		}
	}
}
