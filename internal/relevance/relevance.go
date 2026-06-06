package relevance

import (
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/baseline"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

type ViewMode string

const (
	ViewActionable ViewMode = "actionable"
	ViewAll        ViewMode = "all"
	ViewAudit      ViewMode = "audit"
	ViewCI         ViewMode = "ci"
	ViewEnv        ViewMode = "env"
)

type ActionabilityLevel string

const (
	ActionabilityHigh   ActionabilityLevel = "high"
	ActionabilityMedium ActionabilityLevel = "medium"
	ActionabilityLow    ActionabilityLevel = "low"
)

type FindingView struct {
	Finding       schema.Finding
	Actionability ActionabilityLevel
	NoiseReason   string
}

// Policy controls which findings stay visible in user-facing reports.
type Policy struct {
	IncludeHidden          bool
	MinSeverity            schema.Severity
	View                   ViewMode
	SuppressedIDs          map[string]string
	SuppressedFingerprints map[string]string
}

// Summary describes the effect of applying a Policy.
type Summary struct {
	Visible int
	Hidden  int
}

func DefaultPolicy() Policy {
	return Policy{
		MinSeverity:            schema.SeverityMedium,
		View:                   ViewActionable,
		SuppressedIDs:          make(map[string]string),
		SuppressedFingerprints: make(map[string]string),
	}
}

// PolicyFromReport builds a default policy plus project config suppressions.
func PolicyFromReport(report *schema.Report, includeHidden bool) Policy {
	policy := DefaultPolicy()
	policy.IncludeHidden = includeHidden
	if report == nil {
		return policy
	}
	for _, collector := range report.Collectors {
		if collector.Name != "config" {
			continue
		}
		for _, ev := range collector.Evidence {
			if ev.Source != "devdiag_noise_suppress_finding" {
				continue
			}
			id, reason := parseSuppressionEvidence(ev.Value)
			if id == "" {
				continue
			}
			policy.SuppressedIDs[id] = reason
		}
	}
	return policy
}

// ApplyBaseline merges active (non-expired) baseline entries into the policy's
// SuppressedIDs or SuppressedFingerprints map. Config suppression reasons are not
// overridden by baseline entries.
func ApplyBaseline(policy *Policy, b *baseline.Baseline, now time.Time) {
	if policy == nil || b == nil {
		return
	}
	if policy.SuppressedIDs == nil {
		policy.SuppressedIDs = make(map[string]string)
	}
	if policy.SuppressedFingerprints == nil {
		policy.SuppressedFingerprints = make(map[string]string)
	}
	for _, entry := range baseline.ActiveEntries(b, now) {
		if entry.Fingerprint != "" {
			if _, exists := policy.SuppressedFingerprints[entry.Fingerprint]; !exists {
				policy.SuppressedFingerprints[entry.Fingerprint] = entry.Reason
			}
		} else {
			if _, exists := policy.SuppressedIDs[entry.ID]; !exists {
				policy.SuppressedIDs[entry.ID] = entry.Reason
			}
		}
	}
}

func parseSuppressionEvidence(value string) (id, reason string) {
	parts := strings.SplitN(value, " reason=", 2)
	id = strings.TrimSpace(strings.TrimPrefix(parts[0], "id="))
	if len(parts) == 2 {
		reason = strings.TrimSpace(parts[1])
	}
	return id, reason
}

// FilterReport returns a shallow copy of report with findings filtered by
// policy. Collectors and evidence are preserved so support/debug data remains
// available when included.
func FilterReport(report *schema.Report, policy Policy) (*schema.Report, Summary) {
	if report == nil {
		return nil, Summary{}
	}
	visible := make([]schema.Finding, 0, len(report.Findings))
	var hidden int
	for _, finding := range report.Findings {
		if IsHidden(finding, policy) {
			hidden++
			continue
		}
		visible = append(visible, finding)
	}
	filtered := *report
	filtered.Findings = visible
	return &filtered, Summary{Visible: len(visible), Hidden: hidden}
}

func IsHidden(f schema.Finding, policy Policy) bool {
	if policy.IncludeHidden {
		return false
	}
	if len(policy.SuppressedFingerprints) > 0 {
		fp := baseline.Fingerprint(f)
		if _, ok := policy.SuppressedFingerprints[fp]; ok {
			return true
		}
	}
	if _, ok := policy.SuppressedIDs[f.ID]; ok {
		return true
	}
	switch policy.View {
	case ViewAll, ViewAudit:
		return false
	case ViewCI:
		return !hasFindingPrefix(f, "F-CI-")
	case ViewEnv:
		return !hasFindingPrefix(f, "F-ENV-")
	}
	if isEvidenceOnlyFinding(f) {
		return true
	}
	view := ClassifyFinding(f)
	if view.Actionability == ActionabilityLow {
		return true
	}
	return severityRank(f.Severity) < severityRank(policy.MinSeverity)
}

func ClassifyFinding(f schema.Finding) FindingView {
	view := FindingView{Finding: f, Actionability: ActionabilityLow}
	switch {
	case f.Severity == schema.SeverityCritical || f.Severity == schema.SeverityHigh:
		view.Actionability = ActionabilityHigh
	case f.ID == "F-ENV-001-OPTIONAL":
		view.NoiseReason = "optional env key"
	case f.ID == "F-CI-ENV-DEPLOY-INFO":
		view.NoiseReason = "deployment-only CI env"
	case isEvidenceOnlyFinding(f):
		view.NoiseReason = "evidence-only finding"
	case f.Severity == schema.SeverityMedium:
		view.Actionability = ActionabilityMedium
	case f.Severity == schema.SeverityLow || f.Severity == schema.SeverityInfo:
		view.NoiseReason = "low visibility severity"
	default:
		view.NoiseReason = "unknown actionability"
	}
	return view
}

func hasFindingPrefix(f schema.Finding, prefix string) bool {
	return strings.HasPrefix(strings.ToUpper(f.ID), strings.ToUpper(prefix))
}

func isEvidenceOnlyFinding(f schema.Finding) bool {
	switch f.ID {
	case "F-RUNTIME-DECL-001":
		return true
	default:
		return false
	}
}

func severityRank(severity schema.Severity) int {
	switch severity {
	case schema.SeverityCritical:
		return 4
	case schema.SeverityHigh:
		return 3
	case schema.SeverityMedium:
		return 2
	case schema.SeverityLow:
		return 1
	case schema.SeverityInfo:
		return 0
	default:
		return -1
	}
}
