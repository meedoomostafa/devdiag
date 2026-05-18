package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
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

func TestBuilder_TraceArtifactWithoutCollectors(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	b.SetTraceArtifact([]byte(`{"events":[]}`))
	report := &schema.Report{
		RunID: "test-run-trace",
	}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}

	result, err := InspectFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	var hasSnapshot bool
	var hasTrace bool
	for _, f := range result.FileList {
		if f == "snapshot/" {
			hasSnapshot = true
		}
		if f == "snapshot/trace.json" {
			hasTrace = true
		}
	}
	if !hasSnapshot {
		t.Error("expected snapshot/ directory in capsule")
	}
	if !hasTrace {
		t.Error("expected snapshot/trace.json in capsule")
	}
}

func TestBuilder_TraceArtifactDoesNotDuplicateTraceSnapshot(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	tracePayload := []byte(`{"backend":"strace","events":[]}`)
	b.SetTraceArtifact(tracePayload)
	report := &schema.Report{
		RunID: "test-run-trace-collector",
		Collectors: []schema.CollectorResult{
			{
				Name:   "trace",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "trace_summary", Value: "collector snapshot"},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}
	count, content, err := readTarFileOccurrences(buf.Bytes(), "snapshot/trace.json")
	if err != nil {
		t.Fatalf("read trace artifact: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one snapshot/trace.json entry, got %d", count)
	}
	if !bytes.Equal(content, tracePayload) {
		t.Fatalf("expected trace artifact content %s, got %s", tracePayload, content)
	}
}

func TestBuilder_ManifestNotes_FieldAvailable(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{
		RunID: "test-run-notes",
		Collectors: []schema.CollectorResult{
			{
				Name:   "ok",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "data", Value: "value"},
				},
			},
		},
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
	// Verify the Notes field is empty for normal builds (may be nil due to omitempty)
	if len(result.Manifest.Notes) != 0 {
		t.Errorf("expected no notes, got %v", result.Manifest.Notes)
	}
	// Verify snapshot was included normally
	var hasSnapshot bool
	for _, f := range result.FileList {
		if f == "snapshot/ok.json" {
			hasSnapshot = true
		}
	}
	if !hasSnapshot {
		t.Error("expected snapshot/ok.json to be present")
	}
}

func readTarFileOccurrences(data []byte, name string) (int, []byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	count := 0
	var content []byte
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return count, content, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if h.Name == name {
			count++
			content, err = io.ReadAll(tr)
			if err != nil {
				return 0, nil, err
			}
		}
	}
}
