package relevance

import (
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/baseline"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Policy controls which findings stay visible in user-facing reports.
type Policy struct {
	IncludeHidden bool
	MinSeverity   schema.Severity
	SuppressedIDs map[string]string
}

// Summary describes the effect of applying a Policy.
type Summary struct {
	Visible int
	Hidden  int
}

func DefaultPolicy() Policy {
	return Policy{
		MinSeverity:   schema.SeverityMedium,
		SuppressedIDs: make(map[string]string),
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
// SuppressedIDs map. Config suppression reasons are not overridden by baseline
// entries.
func ApplyBaseline(policy *Policy, b *baseline.Baseline, now time.Time) {
	if policy == nil || b == nil {
		return
	}
	if policy.SuppressedIDs == nil {
		policy.SuppressedIDs = make(map[string]string)
	}
	for _, entry := range baseline.ActiveEntries(b, now) {
		if _, exists := policy.SuppressedIDs[entry.ID]; !exists {
			policy.SuppressedIDs[entry.ID] = entry.Reason
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
	if _, ok := policy.SuppressedIDs[f.ID]; ok {
		return true
	}
	if isEvidenceOnlyFinding(f) {
		return true
	}
	return severityRank(f.Severity) < severityRank(policy.MinSeverity)
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
