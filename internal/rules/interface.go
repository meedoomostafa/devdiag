package rules

import (
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// PolicyEngine evaluates a normalized snapshot and produces findings.
type PolicyEngine interface {
	Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error)
}
