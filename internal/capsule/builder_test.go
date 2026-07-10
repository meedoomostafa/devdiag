package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/redact"
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

func TestBuilder_IncludesMarkdownReportAndRedactionRules(t *testing.T) {
	b := NewBuilder("default", "0.1.0")
	report := &schema.Report{
		SchemaVersion:   "0.1",
		DevDiagVersion:  "0.1.0",
		RunID:           "test-run-format",
		RedactionStatus: "default",
		Findings: []schema.Finding{
			{
				ID:       "F-TEST-001",
				Title:    "redacted test finding",
				Severity: "medium",
				Evidence: []schema.Evidence{
					{Source: "example", Value: "API_KEY=<redacted>"},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}

	reportCount, reportContent, err := readTarFileOccurrences(buf.Bytes(), "report.md")
	if err != nil {
		t.Fatalf("read report.md: %v", err)
	}
	if reportCount != 1 {
		t.Fatalf("expected one report.md entry, got %d", reportCount)
	}
	if !bytes.Contains(reportContent, []byte("# DevDiag Report")) || !bytes.Contains(reportContent, []byte("F-TEST-001")) {
		t.Fatalf("report.md missing expected markdown content: %s", reportContent)
	}
	if bytes.Contains(reportContent, []byte("secret")) {
		t.Fatalf("report.md leaked raw secret-looking value: %s", reportContent)
	}

	rulesCount, rulesContent, err := readTarFileOccurrences(buf.Bytes(), "redaction/rules-applied.json")
	if err != nil {
		t.Fatalf("read redaction rules: %v", err)
	}
	if rulesCount != 1 {
		t.Fatalf("expected one redaction/rules-applied.json entry, got %d", rulesCount)
	}
	if !bytes.Contains(rulesContent, []byte(`"redaction_status": "default"`)) {
		t.Fatalf("redaction rules missing default status: %s", rulesContent)
	}
	if !bytes.Contains(rulesContent, []byte(`"env_values"`)) || !bytes.Contains(rulesContent, []byte(`"url_credentials"`)) {
		t.Fatalf("redaction rules missing expected rule names: %s", rulesContent)
	}
	// The manifest must list exactly the rules the redact engine applies,
	// derived from redact.RuleNames so it cannot drift.
	var applied RedactionRulesApplied
	if err := json.Unmarshal(rulesContent, &applied); err != nil {
		t.Fatalf("parse rules-applied: %v", err)
	}
	want := redact.RuleNames(redact.LevelDefault)
	if len(applied.Rules) != len(want) {
		t.Fatalf("rules-applied = %v, want engine rules %v", applied.Rules, want)
	}
	for i, w := range want {
		if applied.Rules[i] != w {
			t.Errorf("rules-applied[%d] = %q, want %q", i, applied.Rules[i], w)
		}
	}
}

func TestBuilder_StrictRedactionRulesIncludeStrictTokens(t *testing.T) {
	b := NewBuilder("strict", "0.1.0")
	report := &schema.Report{RunID: "r", RedactionStatus: "strict"}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}
	_, rulesContent, err := readTarFileOccurrences(buf.Bytes(), "redaction/rules-applied.json")
	if err != nil {
		t.Fatalf("read redaction rules: %v", err)
	}
	var applied RedactionRulesApplied
	if err := json.Unmarshal(rulesContent, &applied); err != nil {
		t.Fatalf("parse rules-applied: %v", err)
	}
	want := redact.RuleNames(redact.LevelStrict)
	if len(applied.Rules) != len(want) || applied.Rules[len(applied.Rules)-1] != "strict_long_tokens" {
		t.Fatalf("strict rules-applied = %v, want %v", applied.Rules, want)
	}
}

func TestBuilder_OffRedactionRulesEmptyWithNote(t *testing.T) {
	b := NewBuilder("off", "0.1.0")
	report := &schema.Report{RunID: "r", RedactionStatus: "off"}
	var buf bytes.Buffer
	if err := b.Build(&buf, report, nil); err != nil {
		t.Fatalf("Build error: %v", err)
	}
	_, rulesContent, err := readTarFileOccurrences(buf.Bytes(), "redaction/rules-applied.json")
	if err != nil {
		t.Fatalf("read redaction rules: %v", err)
	}
	var applied RedactionRulesApplied
	if err := json.Unmarshal(rulesContent, &applied); err != nil {
		t.Fatalf("parse rules-applied: %v", err)
	}
	if len(applied.Rules) != 0 {
		t.Errorf("off rules = %v, want empty", applied.Rules)
	}
	if applied.ReplacementToken != "" {
		t.Errorf("off replacement token = %q, want empty", applied.ReplacementToken)
	}
	if len(applied.Notes) == 0 || !strings.Contains(applied.Notes[0], "disabled") {
		t.Errorf("off notes = %v, want redaction-disabled note", applied.Notes)
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
