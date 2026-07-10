package collectors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

const defaultCollectorTimeout = 5 * time.Second

// Runner executes a slice of collectors concurrently and aggregates their results.
// Timeout is the configured per-collector budget; 0 means no explicit timeout.
type Runner struct {
	Timeout time.Duration
}

// NewRunner creates a minimal collector runner.
func NewRunner() *Runner {
	return &Runner{Timeout: defaultCollectorTimeout}
}

// Observer receives callbacks about collector execution progress.
type Observer interface {
	CollectorStarted(name string)
	CollectorDone(result schema.CollectorResult, duration time.Duration)
}

type collectorTimeoutProvider interface {
	Timeout() time.Duration
}

type collectorRunResult struct {
	Index  int
	Result schema.CollectorResult
}

type collectorOutcome struct {
	Result schema.CollectorResult
	Err    error
}

// Run executes each collector concurrently with the provided context and returns results.
func (r *Runner) Run(ctx context.Context, collectors []Collector) []schema.CollectorResult {
	return r.RunWithObserver(ctx, collectors, nil)
}

// RunWithObserver executes each collector concurrently and emits observer callbacks.
func (r *Runner) RunWithObserver(ctx context.Context, collectors []Collector, observer Observer) []schema.CollectorResult {
	if ctx == nil {
		ctx = context.Background()
	}

	results := make([]schema.CollectorResult, len(collectors))
	resultCh := make(chan collectorRunResult, len(collectors))

	for i, c := range collectors {
		go func(idx int, col Collector) {
			start := time.Now()
			if observer != nil {
				observer.CollectorStarted(col.Name())
			}
			res := r.runOne(ctx, col)
			if observer != nil {
				observer.CollectorDone(res, time.Since(start))
			}
			resultCh <- collectorRunResult{Index: idx, Result: res}
		}(i, c)
	}

	for range collectors {
		item := <-resultCh
		results[item.Index] = item.Result
	}
	return results
}

func (r *Runner) runOne(ctx context.Context, col Collector) schema.CollectorResult {
	name := col.Name()
	timeout := r.timeoutFor(col)
	if err := ctx.Err(); err != nil {
		return timeoutResult(name, timeout, err, nil)
	}

	collectCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		collectCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	done := make(chan collectorOutcome, 1)
	go func() {
		var outcome collectorOutcome
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("panic: %v", r)
				outcome = collectorOutcome{
					Result: schema.CollectorResult{
						Name:    name,
						Status:  schema.CollectorFailed,
						Notes:   []string{err.Error()},
						Partial: true,
					},
					Err: err,
				}
			}
			done <- outcome
		}()
		res, err := col.Collect(collectCtx)
		outcome = collectorOutcome{Result: res, Err: err}
	}()

	select {
	case outcome := <-done:
		return finalizeResult(name, timeout, collectCtx.Err(), outcome)
	case <-collectCtx.Done():
		select {
		case outcome := <-done:
			return finalizeResult(name, timeout, collectCtx.Err(), outcome)
		case <-time.After(100 * time.Millisecond):
			return timeoutResult(name, timeout, collectCtx.Err(), nil)
		}
	}
}

func (r *Runner) timeoutFor(col Collector) time.Duration {
	if provider, ok := col.(collectorTimeoutProvider); ok {
		if timeout := provider.Timeout(); timeout > 0 {
			return timeout
		}
	}
	if r != nil && r.Timeout > 0 {
		return r.Timeout
	}
	return 0
}

func finalizeResult(name string, timeout time.Duration, ctxErr error, outcome collectorOutcome) schema.CollectorResult {
	res := outcome.Result
	if res.Name == "" {
		res.Name = name
	}
	if outcome.Err == nil {
		if res.Status == "" {
			res.Status = schema.CollectorOK
		}
		return res
	}

	if ctxErr != nil && (errors.Is(outcome.Err, context.DeadlineExceeded) || errors.Is(outcome.Err, context.Canceled)) {
		return timeoutResult(name, timeout, ctxErr, &res)
	}

	res.Status = schema.CollectorFailed
	res.Notes = appendUniqueNote(res.Notes, outcome.Err.Error())
	res.Partial = true
	return res
}

func timeoutResult(name string, timeout time.Duration, err error, partial *schema.CollectorResult) schema.CollectorResult {
	res := schema.CollectorResult{Name: name}
	if partial != nil {
		res = *partial
		if res.Name == "" {
			res.Name = name
		}
	}
	res.Status = schema.CollectorTimeout
	res.Partial = true
	if timeout > 0 {
		res.TimeoutMs = int(timeout.Milliseconds())
	}
	if err != nil {
		res.Notes = appendUniqueNote(res.Notes, err.Error())
	}
	return res
}

func appendUniqueNote(notes []string, note string) []string {
	if note == "" {
		return notes
	}
	for _, existing := range notes {
		if existing == note {
			return notes
		}
	}
	return append(notes, note)
}
