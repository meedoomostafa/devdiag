package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// panicCollector simulates a collector that panics.
type panicCollector struct{}

func (c *panicCollector) Name() string { return "panic" }
func (c *panicCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	panic("intentional panic")
}

// errorCollector simulates a collector that returns an error with partial evidence.
type errorCollector struct{}

func (c *errorCollector) Name() string { return "error" }
func (c *errorCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	return schema.CollectorResult{
		Name:   "error",
		Status: schema.CollectorOK,
		Evidence: []schema.Evidence{
			{Source: "partial", Value: "some evidence"},
		},
	}, errors.New("something went wrong")
}

// okCollector always succeeds.
type okCollector struct{}

func (c *okCollector) Name() string { return "ok" }
func (c *okCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	return schema.CollectorResult{
		Name:   "ok",
		Status: schema.CollectorOK,
		Evidence: []schema.Evidence{
			{Source: "data", Value: "value"},
		},
	}, nil
}

func TestRunner_PanicRecovery(t *testing.T) {
	runner := NewRunner()
	collectors := []Collector{
		&okCollector{},
		&panicCollector{},
		&okCollector{},
	}

	results := runner.Run(context.Background(), collectors)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Panic collector should be marked as failed, not crash the process
	panicResult := results[1]
	if panicResult.Status != schema.CollectorFailed {
		t.Errorf("expected status CollectorFailed for panic collector, got %v", panicResult.Status)
	}
	if panicResult.Name != "panic" {
		t.Errorf("expected name 'panic', got %q", panicResult.Name)
	}
	if len(panicResult.Notes) == 0 || panicResult.Notes[0] != "panic: intentional panic" {
		t.Errorf("expected panic note, got %v", panicResult.Notes)
	}
	if !panicResult.Partial {
		t.Error("expected Partial=true for panic collector")
	}

	// Other collectors should still succeed
	for i, expectedStatus := range []schema.CollectorStatus{schema.CollectorOK, schema.CollectorFailed, schema.CollectorOK} {
		if results[i].Status != expectedStatus {
			t.Errorf("result[%d]: expected status %v, got %v", i, expectedStatus, results[i].Status)
		}
	}
}

func TestRunner_PreservesPartialEvidenceOnError(t *testing.T) {
	runner := NewRunner()
	collectors := []Collector{&errorCollector{}}

	results := runner.Run(context.Background(), collectors)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Status != schema.CollectorFailed {
		t.Errorf("expected status CollectorFailed, got %v", res.Status)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Value != "some evidence" {
		t.Errorf("expected preserved evidence, got %v", res.Evidence)
	}
	if len(res.Notes) == 0 || res.Notes[0] != "something went wrong" {
		t.Errorf("expected error note, got %v", res.Notes)
	}
	if !res.Partial {
		t.Error("expected Partial=true")
	}
}

// slowCollector never returns until its context is cancelled.
type slowCollector struct{}

func (c *slowCollector) Name() string { return "slow" }
func (c *slowCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	<-ctx.Done()
	return schema.CollectorResult{Name: "slow"}, ctx.Err()
}

type contextAwareCollector struct{}

func (c *contextAwareCollector) Name() string { return "context_aware" }
func (c *contextAwareCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	<-ctx.Done()
	return schema.CollectorResult{
		Name: "context_aware",
		Evidence: []schema.Evidence{
			{Source: "partial", Value: "observed before timeout"},
		},
	}, ctx.Err()
}

type ignoringContextCollector struct{}

func (c *ignoringContextCollector) Name() string { return "ignoring_context" }
func (c *ignoringContextCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	select {}
}

type customTimeoutCollector struct{}

func (c *customTimeoutCollector) Name() string { return "custom_timeout" }
func (c *customTimeoutCollector) Timeout() time.Duration {
	return 25 * time.Millisecond
}
func (c *customTimeoutCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	<-ctx.Done()
	return schema.CollectorResult{Name: "custom_timeout"}, ctx.Err()
}

func TestRunner_TimeoutSetsTimeoutMs(t *testing.T) {
	runner := NewRunner()
	runner.Timeout = 100 * time.Millisecond
	// Cancel the context before Run so the pre-loop timeout path triggers
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	collectors := []Collector{&slowCollector{}}
	results := runner.Run(ctx, collectors)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Status != schema.CollectorTimeout {
		t.Errorf("expected status timeout, got %v", res.Status)
	}
	if !res.Partial {
		t.Error("expected Partial=true")
	}
	if res.TimeoutMs != 100 {
		t.Errorf("expected TimeoutMs = 100, got %d", res.TimeoutMs)
	}
}

func TestRunner_NewRunnerConfiguresDefaultTimeout(t *testing.T) {
	runner := NewRunner()
	if runner.Timeout <= 0 {
		t.Fatalf("expected NewRunner to configure a default timeout, got %s", runner.Timeout)
	}
}

func TestRunner_TimeoutCancelsSlowCollector(t *testing.T) {
	runner := NewRunner()
	runner.Timeout = 25 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []schema.CollectorResult, 1)
	go func() {
		done <- runner.Run(ctx, []Collector{&slowCollector{}})
	}()

	var results []schema.CollectorResult
	select {
	case results = <-done:
	case <-time.After(250 * time.Millisecond):
		cancel()
		t.Fatal("runner did not enforce default timeout")
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.Status != schema.CollectorTimeout {
		t.Fatalf("expected timeout status, got %s", res.Status)
	}
	if !res.Partial {
		t.Fatal("expected Partial=true")
	}
	if res.TimeoutMs != 25 {
		t.Fatalf("expected TimeoutMs = 25, got %d", res.TimeoutMs)
	}
}

func TestRunner_ContextDeadlinePreservesPartialEvidenceAsTimeout(t *testing.T) {
	runner := NewRunner()
	runner.Timeout = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []schema.CollectorResult, 1)
	go func() {
		done <- runner.Run(ctx, []Collector{&contextAwareCollector{}})
	}()

	var results []schema.CollectorResult
	select {
	case results = <-done:
	case <-time.After(250 * time.Millisecond):
		cancel()
		t.Fatal("runner did not enforce collector timeout")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Status != schema.CollectorTimeout {
		t.Fatalf("expected timeout status, got %s", res.Status)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Value != "observed before timeout" {
		t.Fatalf("expected preserved partial evidence, got %v", res.Evidence)
	}
	if res.TimeoutMs != 50 {
		t.Fatalf("expected TimeoutMs = 50, got %d", res.TimeoutMs)
	}
}

func TestRunner_ReturnsTimeoutWhenCollectorIgnoresContext(t *testing.T) {
	runner := NewRunner()
	runner.Timeout = 25 * time.Millisecond

	done := make(chan []schema.CollectorResult, 1)
	go func() {
		done <- runner.Run(context.Background(), []Collector{&ignoringContextCollector{}})
	}()

	select {
	case results := <-done:
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].Status != schema.CollectorTimeout {
			t.Fatalf("expected timeout status, got %s", results[0].Status)
		}
		if !results[0].Partial {
			t.Fatal("expected Partial=true")
		}
		if results[0].TimeoutMs != 25 {
			t.Fatalf("expected TimeoutMs = 25, got %d", results[0].TimeoutMs)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("runner blocked on collector that ignored context")
	}
}

func TestRunner_UsesPerCollectorTimeoutOverride(t *testing.T) {
	runner := NewRunner()
	runner.Timeout = 200 * time.Millisecond

	done := make(chan []schema.CollectorResult, 1)
	go func() {
		done <- runner.Run(context.Background(), []Collector{&customTimeoutCollector{}})
	}()

	var results []schema.CollectorResult
	select {
	case results = <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("runner did not enforce per-collector timeout")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != schema.CollectorTimeout {
		t.Fatalf("expected timeout status, got %s", results[0].Status)
	}
	if results[0].TimeoutMs != 25 {
		t.Fatalf("expected TimeoutMs = 25, got %d", results[0].TimeoutMs)
	}
}
