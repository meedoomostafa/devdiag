package collectors

import (
	"context"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Runner executes a slice of collectors and aggregates their results.
type Runner struct{}

// NewRunner creates a minimal collector runner.
func NewRunner() *Runner {
	return &Runner{}
}

// Run executes each collector with the provided context and returns results.
func (r *Runner) Run(ctx context.Context, collectors []Collector) []schema.CollectorResult {
	results := make([]schema.CollectorResult, 0, len(collectors))
	for _, c := range collectors {
		if err := ctx.Err(); err != nil {
			results = append(results, schema.CollectorResult{
				Name:    c.Name(),
				Status:  schema.CollectorTimeout,
				Notes:   []string{err.Error()},
				Partial: true,
			})
			continue
		}
		res, err := c.Collect(ctx)
		if err != nil {
			res = schema.CollectorResult{
				Name:    c.Name(),
				Status:  schema.CollectorFailed,
				Notes:   []string{err.Error()},
				Partial: true,
			}
		}
		results = append(results, res)
	}
	return results
}
