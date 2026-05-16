package collectors

import (
	"context"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector is the interface implemented by every diagnostic collector.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (schema.CollectorResult, error)
}
