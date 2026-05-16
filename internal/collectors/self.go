package collectors

import (
	"context"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

// SelfCollector reports DevDiag's own version and schema info.
type SelfCollector struct{}

func (c *SelfCollector) Name() string {
	return "self"
}

func (c *SelfCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	return schema.CollectorResult{
		Name:   c.Name(),
		Status: schema.CollectorOK,
		Evidence: []schema.Evidence{
			{Source: "version", Value: version.Version},
			{Source: "schema", Value: schema.SchemaVersion},
		},
	}, nil
}
