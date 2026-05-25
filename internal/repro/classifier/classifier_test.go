package classifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifier_PermissionDenied(t *testing.T) {
	c := New()
	results := c.Classify("", "Error: permission denied")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Kind != "permission_denied" {
		t.Errorf("expected permission_denied, got %s", results[0].Kind)
	}
	if results[0].Confidence != 0.7 {
		t.Errorf("expected confidence 0.7, got %f", results[0].Confidence)
	}
}

func TestClassifier_MissingFile(t *testing.T) {
	c := New()
	results := c.Classify("", "No such file or directory")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Kind != "missing_file" {
		t.Errorf("expected missing_file, got %s", results[0].Kind)
	}
}

func TestClassifier_AddressInUse(t *testing.T) {
	c := New()
	results := c.Classify("", "bind: Address already in use")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Kind != "address_in_use" {
		t.Errorf("expected address_in_use, got %s", results[0].Kind)
	}
	if results[0].Confidence != 0.9 {
		t.Errorf("expected confidence 0.9, got %f", results[0].Confidence)
	}
}

func TestClassifier_ConnectionRefused(t *testing.T) {
	c := New()
	results := c.Classify("", "connection refused")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Kind != "connection_refused" {
		t.Errorf("expected connection_refused, got %s", results[0].Kind)
	}
}

func TestClassifier_DependencyFailure(t *testing.T) {
	c := New()
	results := c.Classify("", "npm ERR! could not resolve")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Kind != "dependency_failure" {
		t.Errorf("expected dependency_failure, got %s", results[0].Kind)
	}
}

func TestClassifier_ComposeConfigError(t *testing.T) {
	c := New()
	results := c.Classify("", "Invalid interpolation")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Kind != "compose_config_error" {
		t.Errorf("expected compose_config_error, got %s", results[0].Kind)
	}
}

func TestClassifier_NoMatch(t *testing.T) {
	c := New()
	results := c.Classify("hello world", "success")
	if len(results) != 0 {
		t.Errorf("expected 0 classifications, got %d", len(results))
	}
}

func TestClassifier_VersionNotMatched(t *testing.T) {
	c := New()
	results := c.Classify("", "checking version...")
	if len(results) != 0 {
		t.Errorf("expected 0 classifications for generic 'version', got %d", len(results))
	}
}

func TestClassifier_ExcerptPresent(t *testing.T) {
	c := New()
	results := c.Classify("", "permission denied when opening file")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].Excerpt == "" {
		t.Error("expected non-empty excerpt")
	}
}

func TestClassifier_SourceStreamNotAny(t *testing.T) {
	c := New()
	results := c.Classify("permission denied when reading file", "")
	if len(results) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(results))
	}
	if results[0].SourceStream == "any" {
		t.Error("source_stream should be 'stdout' or 'stderr', not 'any'")
	}
	if results[0].SourceStream != "stdout" {
		t.Errorf("expected source_stream='stdout', got %s", results[0].SourceStream)
	}
}

func TestClassifier_MultipleMatches(t *testing.T) {
	c := New()
	results := c.Classify("permission denied", "address already in use")
	if len(results) < 2 {
		t.Errorf("expected at least 2 classifications, got %d", len(results))
	}
}

func TestClassifier_GoldenFixtures(t *testing.T) {
	fixturesDir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read golden fixtures: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected classifier golden fixtures")
	}

	c := New()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(fixturesDir, entry.Name())
			stdout := readOptionalFixture(t, filepath.Join(dir, "stdout.log"))
			stderr := readOptionalFixture(t, filepath.Join(dir, "stderr.log"))
			expectedData, err := os.ReadFile(filepath.Join(dir, "expected.classifications.json"))
			if err != nil {
				t.Fatalf("read expected classifications: %v", err)
			}
			var expected []classificationExpectation
			if err := json.Unmarshal(expectedData, &expected); err != nil {
				t.Fatalf("parse expected classifications: %v", err)
			}

			results := c.Classify(stdout, stderr)
			if len(results) != len(expected) {
				t.Fatalf("classification count = %d, want %d; results=%+v", len(results), len(expected), results)
			}
			for i, want := range expected {
				got := results[i]
				if got.Kind != want.Kind {
					t.Fatalf("result[%d].kind = %q, want %q", i, got.Kind, want.Kind)
				}
				if got.SourceStream != want.SourceStream {
					t.Fatalf("result[%d].source_stream = %q, want %q", i, got.SourceStream, want.SourceStream)
				}
				if got.PatternID != want.PatternID {
					t.Fatalf("result[%d].pattern_id = %q, want %q", i, got.PatternID, want.PatternID)
				}
				if got.Excerpt == "" {
					t.Fatalf("result[%d] missing excerpt", i)
				}
			}
		})
	}
}

type classificationExpectation struct {
	Kind         string `json:"kind"`
	SourceStream string `json:"source_stream"`
	PatternID    string `json:"pattern_id"`
}

func readOptionalFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(data)
}
