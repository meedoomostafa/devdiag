package findings

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestAggregator_DeduplicatesExactFindingEvidence(t *testing.T) {
	aggregator := NewAggregator()
	findings := []schema.Finding{
		{
			ID:         "F-CI-ENV-001",
			Title:      "CI env var API_KEY not found locally",
			Severity:   schema.SeverityMedium,
			Confidence: 0.6,
			Evidence: []schema.Evidence{
				{Source: "ci_env", Value: "API_KEY"},
				{Source: ".env", Value: "missing"},
			},
		},
		{
			ID:         "F-CI-ENV-001",
			Title:      "CI env var API_KEY not found locally",
			Severity:   schema.SeverityMedium,
			Confidence: 0.6,
			Evidence: []schema.Evidence{
				{Source: "ci_env", Value: "API_KEY"},
				{Source: ".env", Value: "missing"},
			},
		},
	}

	got := aggregator.Add(findings)
	if len(got) != 1 {
		t.Fatalf("expected one deduplicated finding, got %d", len(got))
	}
}

func TestAggregator_KeepsSameIDWithDifferentEvidence(t *testing.T) {
	aggregator := NewAggregator()
	findings := []schema.Finding{
		{
			ID:         "F-CI-ENV-001",
			Title:      "CI env var API_KEY not found locally",
			Severity:   schema.SeverityMedium,
			Confidence: 0.6,
			Evidence: []schema.Evidence{
				{Source: "ci_env", Value: "API_KEY"},
			},
		},
		{
			ID:         "F-CI-ENV-001",
			Title:      "CI env var DB_URL not found locally",
			Severity:   schema.SeverityMedium,
			Confidence: 0.6,
			Evidence: []schema.Evidence{
				{Source: "ci_env", Value: "DB_URL"},
			},
		},
	}

	got := aggregator.Add(findings)
	if len(got) != 2 {
		t.Fatalf("expected two distinct findings, got %d", len(got))
	}
}

func TestAggregator_PopulatesFindingContractDefaults(t *testing.T) {
	aggregator := NewAggregator()
	findings := []schema.Finding{
		{
			ID:         "F-CI-RUNTIME-001",
			Title:      "CI runtime differs from local",
			Severity:   schema.SeverityMedium,
			Confidence: 0.7,
		},
	}

	got := aggregator.Add(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if len(got[0].Layers) == 0 {
		t.Fatal("expected default layers to be populated")
	}
	if got[0].RedactionStatus == "" {
		t.Fatal("expected redaction status to be populated")
	}
	if len(got[0].Fixes) == 0 {
		t.Fatal("expected default fixes to be populated")
	}
}
