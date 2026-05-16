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
