package schema

// Severity represents the risk level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents a single diagnostic finding.
type Finding struct {
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	Severity        Severity   `json:"severity"`
	Confidence      float64    `json:"confidence"`
	Layers          []string   `json:"layers,omitempty"`
	Symptom         string     `json:"symptom"`
	Evidence        []Evidence `json:"evidence,omitempty"`
	LikelyCauses    []string   `json:"likely_causes,omitempty"`
	Fixes           []Fix      `json:"fixes,omitempty"`
	RedactionStatus string     `json:"redaction_status"`
}
