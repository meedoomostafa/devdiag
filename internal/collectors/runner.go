package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Runner executes a slice of collectors concurrently and aggregates their results.
// Timeout is the configured per-collector budget; 0 means no explicit timeout.
type Runner struct {
	Timeout time.Duration
}

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
			timeoutMs := 0
			if r.Timeout > 0 {
				timeoutMs = int(r.Timeout.Milliseconds())
			}
			results[i] = schema.CollectorResult{
				Name:      c.Name(),
				Status:    schema.CollectorTimeout,
				Notes:     []string{err.Error()},
				Partial:   true,
				TimeoutMs: timeoutMs,
			}
			continue
		}

		wg.Add(1)
		go func(idx int, col Collector) {
			defer wg.Done()

			var res schema.CollectorResult
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						res = schema.CollectorResult{
							Name:    col.Name(),
							Status:  schema.CollectorFailed,
							Notes:   []string{fmt.Sprintf("panic: %v", r)},
							Partial: true,
						}
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				res, err = col.Collect(ctx)
			}()

			if err != nil {
				// Preserve any partial evidence already collected
				if res.Name == "" {
					res.Name = col.Name()
				}
				res.Status = schema.CollectorFailed
				res.Notes = append(res.Notes, err.Error())
				res.Partial = true
			}
			results[idx] = res
		}(i, c)
	}

	wg.Wait()
	return results
}
