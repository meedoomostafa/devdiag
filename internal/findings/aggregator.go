package findings

import (
	"sort"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Aggregator sorts findings by severity descending, then confidence descending.
type Aggregator struct{}

// NewAggregator creates a new aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{}
}

// Add collects findings and returns a stable-sorted slice.
func (a *Aggregator) Add(findings []schema.Finding) []schema.Finding {
	deduped := make([]schema.Finding, 0, len(findings))
	seen := make(map[string]int, len(findings))
	for _, finding := range findings {
		normalized := normalizeFinding(finding)
		key := findingFingerprint(normalized)
		if existingIdx, ok := seen[key]; ok {
			if ranksBefore(normalized, deduped[existingIdx]) {
				deduped[existingIdx] = normalized
			}
			continue
		}
		seen[key] = len(deduped)
		deduped = append(deduped, normalized)
	}

	sorted := make([]schema.Finding, len(deduped))
	copy(sorted, deduped)
	sort.SliceStable(sorted, func(i, j int) bool {
		return ranksBefore(sorted[i], sorted[j])
	})
	return sorted
}

func normalizeFinding(f schema.Finding) schema.Finding {
	if len(f.Layers) == 0 {
		f.Layers = defaultLayers(f.ID)
	}
	if f.RedactionStatus == "" {
		f.RedactionStatus = "default"
	}
	if len(f.Fixes) == 0 {
		f.Fixes = []schema.Fix{
			{
				Class: schema.FixManual,
				Title: "Review the finding and apply the recommended remediation",
			},
		}
	}
	return f
}

func defaultLayers(id string) []string {
	switch {
	case strings.HasPrefix(id, "F-CI-"):
		return []string{"ci", "local"}
	case strings.HasPrefix(id, "F-ENV-"):
		return []string{"env"}
	case strings.HasPrefix(id, "F-GIT-"):
		return []string{"git"}
	case strings.HasPrefix(id, "F-FS-"):
		return []string{"filesystem"}
	case strings.HasPrefix(id, "F-CONTAINER-"):
		return []string{"containers"}
	case strings.HasPrefix(id, "F-GPU-"), strings.HasPrefix(id, "F-AI-"):
		return []string{"host", "runtime"}
	case strings.HasPrefix(id, "F-CACHE-"):
		return []string{"cache"}
	case strings.HasPrefix(id, "F-TRACE-"):
		return []string{"process"}
	default:
		return []string{"diagnostic"}
	}
}

func findingFingerprint(f schema.Finding) string {
	parts := make([]string, 0, len(f.Evidence))
	for _, ev := range f.Evidence {
		parts = append(parts, ev.Source+"\x00"+ev.Value)
	}
	sort.Strings(parts)
	return f.ID + "\x00" + strings.Join(parts, "\x00")
}

func ranksBefore(a, b schema.Finding) bool {
	ai := severityRank(a.Severity)
	bi := severityRank(b.Severity)
	if ai != bi {
		return ai < bi
	}
	return a.Confidence > b.Confidence
}

func severityRank(severity schema.Severity) int {
	switch severity {
	case schema.SeverityCritical:
		return 0
	case schema.SeverityHigh:
		return 1
	case schema.SeverityMedium:
		return 2
	case schema.SeverityLow:
		return 3
	case schema.SeverityInfo:
		return 4
	default:
		return 5
	}
}
