package rules

import (
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// StubEngine is the M0 placeholder policy engine.
type StubEngine struct{}

// NewStubEngine creates the stub engine.
func NewStubEngine() *StubEngine {
	return &StubEngine{}
}

// Evaluate returns a single info-level stub finding.
func (e *StubEngine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	return []schema.Finding{
		{
			ID:              "F-SELF-000",
			Title:           "Milestone 0 active: no deterministic policies loaded yet",
			Severity:        schema.SeverityInfo,
			Confidence:      1.0,
			Layers:          []string{"internal"},
			Symptom:         "DevDiag is running in skeleton mode",
			Evidence:        []schema.Evidence{},
			LikelyCauses:    []string{"Milestone 0 does not include real collectors or policies"},
			Fixes:           []schema.Fix{},
			RedactionStatus: "safe",
		},
	}, nil
}
