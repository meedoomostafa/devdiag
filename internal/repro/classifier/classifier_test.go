package classifier

import (
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
