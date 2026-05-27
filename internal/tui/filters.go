package tui

import (
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// ActiveFilters holds the current filter state.
type ActiveFilters struct {
	Severity      []schema.Severity
	Domain        string
	ConfidenceMin float64
	MutationRisk  string
	Text          string
}

// DefaultFilters returns an unfiltered state.
func DefaultFilters() ActiveFilters {
	return ActiveFilters{
		Severity: []schema.Severity{
			schema.SeverityCritical,
			schema.SeverityHigh,
			schema.SeverityMedium,
			schema.SeverityLow,
			schema.SeverityInfo,
		},
		ConfidenceMin: 0.0,
	}
}

// Match returns true if the finding passes all active filters.
func (af ActiveFilters) Match(f InspectFinding) bool {
	if len(af.Severity) > 0 {
		found := false
		for _, s := range af.Severity {
			if f.Finding.Severity == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if af.Domain != "" && !strings.EqualFold(f.Domain, af.Domain) {
		return false
	}
	if f.Finding.Confidence < af.ConfidenceMin {
		return false
	}
	if af.MutationRisk != "" && !strings.EqualFold(f.MutationRisk, af.MutationRisk) {
		return false
	}
	if af.Text != "" {
		text := strings.ToLower(af.Text)
		match := strings.Contains(strings.ToLower(f.Finding.ID), text) ||
			strings.Contains(strings.ToLower(f.Finding.Title), text) ||
			strings.Contains(strings.ToLower(f.Domain), text) ||
			strings.Contains(strings.ToLower(f.Finding.Symptom), text)
		if !match {
			return false
		}
	}
	return true
}

// ApplyFilters rebuilds the filtered list from all findings.
func ApplyFilters(findings []InspectFinding, af ActiveFilters) []InspectFinding {
	out := make([]InspectFinding, 0, len(findings))
	for _, f := range findings {
		if af.Match(f) {
			out = append(out, f)
		}
	}
	return out
}

// severityFromString parses a severity string, returning empty string if invalid.
func severityFromString(s string) schema.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return schema.SeverityCritical
	case "high":
		return schema.SeverityHigh
	case "medium":
		return schema.SeverityMedium
	case "low":
		return schema.SeverityLow
	case "info":
		return schema.SeverityInfo
	}
	return ""
}
