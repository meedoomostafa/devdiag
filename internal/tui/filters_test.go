package tui

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestActiveFilters_Match_AllPass(t *testing.T) {
	af := DefaultFilters()
	f := InspectFinding{Finding: schema.Finding{Severity: schema.SeverityHigh, Confidence: 0.9, ID: "F-TEST-001"}}
	if !af.Match(f) {
		t.Error("default filters should match any finding")
	}
}

func TestActiveFilters_Match_Severity(t *testing.T) {
	af := DefaultFilters()
	af.Severity = []schema.Severity{schema.SeverityCritical}
	f := InspectFinding{Finding: schema.Finding{Severity: schema.SeverityHigh}}
	if af.Match(f) {
		t.Error("should not match when severity is excluded")
	}
}

func TestActiveFilters_Match_Domain(t *testing.T) {
	af := DefaultFilters()
	af.Domain = "ci"
	f := InspectFinding{Finding: schema.Finding{ID: "F-CI-001", Severity: schema.SeverityHigh}, Domain: "ci"}
	if !af.Match(f) {
		t.Error("should match exact domain")
	}
	f2 := InspectFinding{Finding: schema.Finding{ID: "F-ENV-001", Severity: schema.SeverityHigh}, Domain: "env"}
	if af.Match(f2) {
		t.Error("should not match different domain")
	}
}

func TestActiveFilters_Match_ConfidenceMin(t *testing.T) {
	af := DefaultFilters()
	af.ConfidenceMin = 0.8
	f := InspectFinding{Finding: schema.Finding{Severity: schema.SeverityHigh, Confidence: 0.9}}
	if !af.Match(f) {
		t.Error("should match above threshold")
	}
	f2 := InspectFinding{Finding: schema.Finding{Severity: schema.SeverityHigh, Confidence: 0.5}}
	if af.Match(f2) {
		t.Error("should not match below threshold")
	}
}

func TestActiveFilters_Match_MutationRisk(t *testing.T) {
	af := DefaultFilters()
	af.MutationRisk = "high"
	f := InspectFinding{Finding: schema.Finding{Severity: schema.SeverityHigh}, MutationRisk: "high"}
	if !af.Match(f) {
		t.Error("should match exact mutation risk")
	}
	f2 := InspectFinding{Finding: schema.Finding{Severity: schema.SeverityHigh}, MutationRisk: "low"}
	if af.Match(f2) {
		t.Error("should not match different mutation risk")
	}
}

func TestActiveFilters_Match_Text(t *testing.T) {
	af := DefaultFilters()
	af.Text = "CI"
	f := InspectFinding{Finding: schema.Finding{ID: "F-CI-001", Severity: schema.SeverityHigh, Title: "CI drift"}}
	if !af.Match(f) {
		t.Error("should match text in ID")
	}
	f2 := InspectFinding{Finding: schema.Finding{ID: "F-ENV-001", Severity: schema.SeverityHigh, Title: "Secret"}}
	if af.Match(f2) {
		t.Error("should not match unrelated finding")
	}
}

func TestApplyFilters(t *testing.T) {
	findings := []InspectFinding{
		{Finding: schema.Finding{Severity: schema.SeverityHigh, ID: "A"}},
		{Finding: schema.Finding{Severity: schema.SeverityMedium, ID: "B"}},
		{Finding: schema.Finding{Severity: schema.SeverityInfo, ID: "C"}},
	}
	af := DefaultFilters()
	af.Severity = []schema.Severity{schema.SeverityHigh, schema.SeverityMedium}
	filtered := ApplyFilters(findings, af)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(filtered))
	}
}

func TestSeverityFromString(t *testing.T) {
	tests := []struct {
		input string
		want  schema.Severity
	}{
		{"critical", schema.SeverityCritical},
		{"high", schema.SeverityHigh},
		{"medium", schema.SeverityMedium},
		{"low", schema.SeverityLow},
		{"info", schema.SeverityInfo},
		{"unknown", ""},
	}
	for _, tt := range tests {
		got := severityFromString(tt.input)
		if got != tt.want {
			t.Errorf("severityFromString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
