package relevance

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestFilterReport_DefaultHidesLowInfoAndEvidenceOnlyFindings(t *testing.T) {
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-HIGH-001", Severity: schema.SeverityHigh, Title: "High"},
			{ID: "F-MEDIUM-001", Severity: schema.SeverityMedium, Title: "Medium"},
			{ID: "F-LOW-001", Severity: schema.SeverityLow, Title: "Low"},
			{ID: "F-RUNTIME-DECL-001", Severity: schema.SeverityInfo, Title: "Runtime declaration"},
		},
	}

	filtered, summary := FilterReport(report, DefaultPolicy())
	if summary.Hidden != 2 {
		t.Fatalf("hidden = %d, want 2", summary.Hidden)
	}
	if len(filtered.Findings) != 2 {
		t.Fatalf("visible findings = %d, want 2: %v", len(filtered.Findings), filtered.Findings)
	}
	for _, finding := range filtered.Findings {
		if finding.Severity == schema.SeverityLow || finding.Severity == schema.SeverityInfo {
			t.Fatalf("unexpected hidden finding stayed visible: %v", finding)
		}
	}
}

func TestFilterReport_IncludeHiddenKeepsEverything(t *testing.T) {
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-LOW-001", Severity: schema.SeverityLow, Title: "Low"},
			{ID: "F-RUNTIME-DECL-001", Severity: schema.SeverityInfo, Title: "Runtime declaration"},
		},
	}
	policy := DefaultPolicy()
	policy.IncludeHidden = true

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 0 {
		t.Fatalf("hidden = %d, want 0", summary.Hidden)
	}
	if len(filtered.Findings) != 2 {
		t.Fatalf("visible findings = %d, want 2", len(filtered.Findings))
	}
}

func TestPolicyFromReport_HidesConfiguredSuppression(t *testing.T) {
	report := &schema.Report{
		Collectors: []schema.CollectorResult{
			{
				Name: "config",
				Evidence: []schema.Evidence{
					{Source: "devdiag_noise_suppress_finding", Value: "id=F-CI-SHELL-001 reason=intentional shell split"},
				},
			},
		},
		Findings: []schema.Finding{
			{ID: "F-CI-SHELL-001", Severity: schema.SeverityMedium, Title: "Shell mismatch"},
		},
	}

	filtered, summary := FilterReport(report, PolicyFromReport(report, false))
	if summary.Hidden != 1 {
		t.Fatalf("hidden = %d, want 1", summary.Hidden)
	}
	if len(filtered.Findings) != 0 {
		t.Fatalf("expected suppression to hide finding, got %v", filtered.Findings)
	}
}
