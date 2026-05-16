package schema

// Evidence represents a single piece of evidence for a finding.
type Evidence struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}
