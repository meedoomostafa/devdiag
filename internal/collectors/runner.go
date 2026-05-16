package collectors

import (
	"context"
	"sync"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Runner executes a slice of collectors concurrently and aggregates their results.
type Runner struct{}

// NewRunner creates a minimal collector runner.
func NewRunner() *Runner {
	return &Runner{}
}

// Run executes each collector concurrently with the provided context and returns results.
func (r *Runner) Run(ctx context.Context, collectors []Collector) []schema.CollectorResult {
	results := make([]schema.CollectorResult, len(collectors))
	var wg sync.WaitGroup

	for i, c := range collectors {
		if err := ctx.Err(); err != nil {
			results[i] = schema.CollectorResult{
				Name:    c.Name(),
				Status:  schema.CollectorTimeout,
				Notes:   []string{err.Error()},
				Partial: true,
			}
			continue
		}

		wg.Add(1)
		go func(idx int, col Collector) {
			defer wg.Done()
			res, err := col.Collect(ctx)
			if err != nil {
				res = schema.CollectorResult{
					Name:    col.Name(),
					Status:  schema.CollectorFailed,
					Notes:   []string{err.Error()},
					Partial: true,
				}
			}
			results[idx] = res
		}(i, c)
	}

	wg.Wait()
	return results
}
