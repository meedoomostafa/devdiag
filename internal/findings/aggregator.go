package findings

import (
	"sort"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Aggregator sorts findings by severity descending, then confidence descending.
// Deduplication by ID will be added when multiple policy sources exist.
type Aggregator struct{}

// NewAggregator creates a new aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{}
}

// Add collects findings and returns a stable-sorted slice.
func (a *Aggregator) Add(findings []schema.Finding) []schema.Finding {
	// Sort: critical > high > medium > low > info, then by confidence desc.
	severityOrder := map[schema.Severity]int{
		schema.SeverityCritical: 0,
		schema.SeverityHigh:     1,
		schema.SeverityMedium:   2,
		schema.SeverityLow:      3,
		schema.SeverityInfo:     4,
	}

	sorted := make([]schema.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		si := severityOrder[sorted[i].Severity]
		sj := severityOrder[sorted[j].Severity]
		if si != sj {
			return si < sj
		}
		return sorted[i].Confidence > sorted[j].Confidence
	})
	return sorted
}
