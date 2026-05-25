package graph

import (
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// NormalizedSnapshot is the normalized diagnostic graph.
type NormalizedSnapshot struct {
	Collectors []schema.CollectorResult `json:"collectors"`
}

// SnapshotBuilder builds a NormalizedSnapshot from collector results.
type SnapshotBuilder struct{}

// NewSnapshotBuilder creates a builder.
func NewSnapshotBuilder() *SnapshotBuilder {
	return &SnapshotBuilder{}
}

// Build constructs a snapshot from collector results.
// Never panics on partial data.
func (b *SnapshotBuilder) Build(results []schema.CollectorResult) NormalizedSnapshot {
	return NormalizedSnapshot{
		Collectors: results,
	}
}
