package relevance

import (
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/baseline"
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

func TestApplyBaselineSuppressesFinding(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
			{ID: "F-HIGH-001", Severity: schema.SeverityHigh, Title: "High issue"},
		},
	}
	policy := DefaultPolicy()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted for v1.0", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 1 {
		t.Fatalf("hidden = %d, want 1", summary.Hidden)
	}
	if len(filtered.Findings) != 1 {
		t.Fatalf("visible = %d, want 1", len(filtered.Findings))
	}
	if filtered.Findings[0].ID != "F-HIGH-001" {
		t.Fatalf("remaining finding = %q, want F-HIGH-001", filtered.Findings[0].ID)
	}
}

func TestApplyBaselineExpiredEntryDoesNotSuppress(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
		},
	}
	policy := DefaultPolicy()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "old", CreatedAt: now, ExpiresAt: &past},
		},
	}
	ApplyBaseline(&policy, b, now)

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 0 {
		t.Fatalf("hidden = %d, want 0 (expired entry should not suppress)", summary.Hidden)
	}
	if len(filtered.Findings) != 1 {
		t.Fatalf("visible = %d, want 1", len(filtered.Findings))
	}
}

func TestApplyBaselineDoesNotOverrideConfigSuppression(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.SuppressedIDs["F-ENV-001"] = "config reason"

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "baseline reason", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	if policy.SuppressedIDs["F-ENV-001"] != "config reason" {
		t.Fatalf("expected config reason to be preserved, got %q", policy.SuppressedIDs["F-ENV-001"])
	}
}

func TestApplyBaselineNilBaseline(t *testing.T) {
	policy := DefaultPolicy()
	ApplyBaseline(&policy, nil, time.Now())
	if len(policy.SuppressedIDs) != 0 {
		t.Fatalf("expected empty SuppressedIDs, got %v", policy.SuppressedIDs)
	}
}

func TestApplyBaselineNilPolicy(t *testing.T) {
	now := time.Now()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "test", CreatedAt: now},
		},
	}
	// Should not panic
	ApplyBaseline(nil, b, now)
}

func TestIncludeHiddenMakesBaselinedFindingsVisible(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
		},
	}
	policy := DefaultPolicy()
	policy.IncludeHidden = true
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 0 {
		t.Fatalf("hidden = %d, want 0 (include-hidden should show baselined findings)", summary.Hidden)
	}
	if len(filtered.Findings) != 1 {
		t.Fatalf("visible = %d, want 1", len(filtered.Findings))
	}
}

func TestBaselineAndConfigSuppressionBothSuppress(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	report := &schema.Report{
		Collectors: []schema.CollectorResult{
			{
				Name: "config",
				Evidence: []schema.Evidence{
					{Source: "devdiag_noise_suppress_finding", Value: "id=F-CI-SHELL-001 reason=config suppression"},
				},
			},
		},
		Findings: []schema.Finding{
			{ID: "F-CI-SHELL-001", Severity: schema.SeverityMedium, Title: "Shell mismatch"},
			{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env issue"},
			{ID: "F-HIGH-001", Severity: schema.SeverityHigh, Title: "High issue"},
		},
	}
	policy := PolicyFromReport(report, false)
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "baseline suppression", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 2 {
		t.Fatalf("hidden = %d, want 2 (one from config, one from baseline)", summary.Hidden)
	}
	if len(filtered.Findings) != 1 {
		t.Fatalf("visible = %d, want 1", len(filtered.Findings))
	}
	if filtered.Findings[0].ID != "F-HIGH-001" {
		t.Fatalf("remaining = %q, want F-HIGH-001", filtered.Findings[0].ID)
	}
}

func TestFingerprintBaselineDoesNotSuppressSameIDDifferentSymptom(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	f1 := schema.Finding{ID: "F-ENV-001", Symptom: "symptom 1", Severity: schema.SeverityMedium}
	f2 := schema.Finding{ID: "F-ENV-001", Symptom: "symptom 2", Severity: schema.SeverityMedium}

	report := &schema.Report{
		Findings: []schema.Finding{f1, f2},
	}
	policy := DefaultPolicy()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Fingerprint: baseline.Fingerprint(f1), Reason: "accepted 1", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 1 {
		t.Fatalf("expected 1 hidden, got %d", summary.Hidden)
	}
	if len(filtered.Findings) != 1 {
		t.Fatalf("expected 1 visible, got %d", len(filtered.Findings))
	}
	if filtered.Findings[0].Symptom != "symptom 2" {
		t.Fatalf("expected symptom 2 to remain visible, got %q", filtered.Findings[0].Symptom)
	}
}

func TestIDBaselineStillSuppressesAllSameIDFindings(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	f1 := schema.Finding{ID: "F-ENV-001", Symptom: "symptom 1", Severity: schema.SeverityMedium}
	f2 := schema.Finding{ID: "F-ENV-001", Symptom: "symptom 2", Severity: schema.SeverityMedium}

	report := &schema.Report{
		Findings: []schema.Finding{f1, f2},
	}
	policy := DefaultPolicy()
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Reason: "accepted ID-only", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	_, summary := FilterReport(report, policy)
	if summary.Hidden != 2 {
		t.Fatalf("expected both same-ID findings to be hidden, got %d", summary.Hidden)
	}
}

func TestIncludeHiddenBypassesFingerprintSuppression(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	f1 := schema.Finding{ID: "F-ENV-001", Symptom: "symptom 1", Severity: schema.SeverityMedium}

	report := &schema.Report{
		Findings: []schema.Finding{f1},
	}
	policy := DefaultPolicy()
	policy.IncludeHidden = true
	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Fingerprint: baseline.Fingerprint(f1), Reason: "accepted 1", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	_, summary := FilterReport(report, policy)
	if summary.Hidden != 0 {
		t.Fatalf("expected 0 hidden under IncludeHidden, got %d", summary.Hidden)
	}
}

func TestApplyBaselineDoesNotOverrideExistingFingerprintReason(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	f1 := schema.Finding{ID: "F-ENV-001", Symptom: "symptom 1", Severity: schema.SeverityMedium}
	fp := baseline.Fingerprint(f1)

	policy := DefaultPolicy()
	policy.SuppressedFingerprints[fp] = "original config reason"

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		Entries: []baseline.Entry{
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "baseline override", CreatedAt: now},
		},
	}
	ApplyBaseline(&policy, b, now)

	if policy.SuppressedFingerprints[fp] != "original config reason" {
		t.Fatalf("expected config reason to be preserved, got %q", policy.SuppressedFingerprints[fp])
	}
}

func TestFilterReport_ViewAllShowsLowInfoButKeepsSuppressions(t *testing.T) {
	report := &schema.Report{
		Collectors: []schema.CollectorResult{
			{
				Name: "config",
				Evidence: []schema.Evidence{
					{Source: "devdiag_noise_suppress_finding", Value: "id=F-SUPPRESSED-001 reason=accepted noise"},
				},
			},
		},
		Findings: []schema.Finding{
			{ID: "F-LOW-001", Severity: schema.SeverityLow, Title: "Low"},
			{ID: "F-RUNTIME-DECL-001", Severity: schema.SeverityInfo, Title: "Runtime declaration"},
			{ID: "F-SUPPRESSED-001", Severity: schema.SeverityMedium, Title: "Suppressed"},
		},
	}
	policy := PolicyFromReport(report, false)
	policy.View = ViewAll

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 1 {
		t.Fatalf("hidden = %d, want 1 suppressed finding", summary.Hidden)
	}
	if len(filtered.Findings) != 2 {
		t.Fatalf("visible findings = %d, want 2: %+v", len(filtered.Findings), filtered.Findings)
	}
	for _, finding := range filtered.Findings {
		if finding.ID == "F-SUPPRESSED-001" {
			t.Fatalf("suppressed finding should stay hidden in --view all without --include-hidden")
		}
	}
}

func TestFilterReport_ViewCIShowsDeployOnlyInfo(t *testing.T) {
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-CI-ENV-DEPLOY-INFO", Severity: schema.SeverityInfo, Title: "Deploy-only"},
			{ID: "F-CI-ENV-001", Severity: schema.SeverityMedium, Title: "CI local mismatch"},
			{ID: "F-ENV-001", Severity: schema.SeverityMedium, Title: "Env mismatch"},
		},
	}
	policy := DefaultPolicy()
	policy.View = ViewCI

	filtered, summary := FilterReport(report, policy)
	if summary.Hidden != 1 {
		t.Fatalf("hidden = %d, want 1 non-CI finding", summary.Hidden)
	}
	if len(filtered.Findings) != 2 {
		t.Fatalf("visible findings = %d, want 2: %+v", len(filtered.Findings), filtered.Findings)
	}
	for _, finding := range filtered.Findings {
		if finding.ID == "F-ENV-001" {
			t.Fatalf("env finding should be hidden in ci view")
		}
	}
}

func TestClassifyFindingActionability(t *testing.T) {
	tests := []struct {
		name string
		f    schema.Finding
		want ActionabilityLevel
	}{
		{name: "high severity", f: schema.Finding{ID: "F-ENV-001", Severity: schema.SeverityHigh}, want: ActionabilityHigh},
		{name: "optional env", f: schema.Finding{ID: "F-ENV-001-OPTIONAL", Severity: schema.SeverityInfo}, want: ActionabilityLow},
		{name: "deploy info", f: schema.Finding{ID: "F-CI-ENV-DEPLOY-INFO", Severity: schema.SeverityInfo}, want: ActionabilityLow},
		{name: "required env", f: schema.Finding{ID: "F-ENV-001", Severity: schema.SeverityMedium, Confidence: 0.7}, want: ActionabilityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := ClassifyFinding(tt.f)
			if view.Actionability != tt.want {
				t.Fatalf("actionability = %s, want %s", view.Actionability, tt.want)
			}
		})
	}
}
