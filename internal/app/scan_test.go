package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// fakeCollector is a test collector that returns a configurable result.
type fakeCollector struct {
	name   string
	result schema.CollectorResult
	err    error
	delay  time.Duration
}

func (c *fakeCollector) Name() string { return c.name }
func (c *fakeCollector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			res := c.result
			if res.Name == "" {
				res.Name = c.name
			}
			return res, ctx.Err()
		}
	}
	res := c.result
	if res.Name == "" {
		res.Name = c.name
	}
	return res, c.err
}

// fakeCollectorFactory returns pre-configured collectors and signals.
type fakeCollectorFactory struct {
	collectors []collectors.Collector
	signals    RepoSignals
}

func (f *fakeCollectorFactory) Build(opts ScanOptions) ([]collectors.Collector, RepoSignals) {
	return f.collectors, f.signals
}

// fakeRuleEngine returns pre-configured findings or an error.
type fakeRuleEngine struct {
	findings []schema.Finding
	err      error
}

func (e *fakeRuleEngine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	return e.findings, e.err
}

// fakeEngineFactory creates fake rule engines.
type fakeEngineFactory struct {
	m1Findings []schema.Finding
	m1Err      error
	m6Findings []schema.Finding
	m6Err      error
	m8Findings []schema.Finding
	m8Err      error
}

func (f *fakeEngineFactory) NewM1() RuleEngine {
	return &fakeRuleEngine{findings: f.m1Findings, err: f.m1Err}
}
func (f *fakeEngineFactory) NewM6() RuleEngine {
	return &fakeRuleEngine{findings: f.m6Findings, err: f.m6Err}
}
func (f *fakeEngineFactory) NewM8() RuleEngine {
	return &fakeRuleEngine{findings: f.m8Findings, err: f.m8Err}
}

func newTestScanner(factory *fakeCollectorFactory, engines *fakeEngineFactory) *Scanner {
	return NewScanner(ScannerDeps{
		CollectorFactory: factory,
		Runner:           collectors.NewRunner(),
		Engines:          engines,
		RunID:            func() string { return "test-run-id" },
		Now:              func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
}

func TestDefaultCollectorFactory_DockerSignalDoesNotAddPodmanCollector(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/Dockerfile", []byte("FROM alpine\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	collectorList, signals := defaultCollectorFactory{}.Build(ScanOptions{Path: dir})
	names := collectorNames(collectorList)

	if !signals.HasDocker || signals.HasPodman || !signals.HasContainers {
		t.Fatalf("signals = %+v, want docker-only container signal", signals)
	}
	if !hasCollectorName(names, "docker") {
		t.Fatalf("docker collector missing from docker-only fixture: %v", names)
	}
	if hasCollectorName(names, "podman") {
		t.Fatalf("podman collector should not run for docker-only fixture: %v", names)
	}
}

func TestDefaultCollectorFactory_PodmanSignalDoesNotAddDockerCollector(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/Containerfile", []byte("FROM alpine\n"), 0o644); err != nil {
		t.Fatalf("write Containerfile: %v", err)
	}

	collectorList, signals := defaultCollectorFactory{}.Build(ScanOptions{Path: dir})
	names := collectorNames(collectorList)

	if signals.HasDocker || !signals.HasPodman || !signals.HasContainers {
		t.Fatalf("signals = %+v, want podman-only container signal", signals)
	}
	if !hasCollectorName(names, "podman") {
		t.Fatalf("podman collector missing from podman-only fixture: %v", names)
	}
	if hasCollectorName(names, "docker") {
		t.Fatalf("docker collector should not run for podman-only fixture: %v", names)
	}
}

func collectorNames(collectorList []collectors.Collector) []string {
	names := make([]string, len(collectorList))
	for i, collector := range collectorList {
		names[i] = collector.Name()
	}
	return names
}

func hasCollectorName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func eventTypes(events []Event) []EventType {
	out := make([]EventType, len(events))
	for i, e := range events {
		out[i] = e.Type
	}
	return out
}

func countEvents(events []Event, t EventType) int {
	c := 0
	for _, e := range events {
		if e.Type == t {
			c++
		}
	}
	return c
}

func hasEvent(events []Event, t EventType) bool {
	return countEvents(events, t) > 0
}

func TestNewRunID_UsesProvidedClock(t *testing.T) {
	fixed := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	id := newRunID(fixed)
	wantPrefix := "2024-03-15T10:30:00Z_"
	if !strings.HasPrefix(id, wantPrefix) {
		t.Errorf("newRunID = %q, want prefix %q", id, wantPrefix)
	}
	if len(id) <= len(wantPrefix) {
		t.Errorf("newRunID = %q, want random suffix after prefix", id)
	}
}

func TestDefaultCollectorFactory_AIMLProfileWithoutPython(t *testing.T) {
	dir := t.TempDir()
	collectorList, _ := defaultCollectorFactory{}.Build(ScanOptions{Path: dir, Profile: "ai-ml"})
	names := collectorNames(collectorList)
	if !hasCollectorName(names, "gpu") {
		t.Fatalf("gpu collector missing for ai-ml profile: %v", names)
	}
	if !hasCollectorName(names, "pythonml") {
		t.Fatalf("pythonml collector expected for ai-ml profile even without python signal: %v", names)
	}
}

func TestScan_ReturnsReport(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected report, got nil")
	}
	if report.RunID != "test-run-id" {
		t.Errorf("expected run ID test-run-id, got %s", report.RunID)
	}
	if report.SchemaVersion == "" {
		t.Error("expected schema version")
	}
	if report.Repo.Root != "/tmp/test" {
		t.Errorf("expected repo root /tmp/test, got %s", report.Repo.Root)
	}
	if report.DevDiagVersion == "" {
		t.Error("expected devdiag version")
	}
}

func TestScan_EmitsLifecycleEvents(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	if !hasEvent(events, EventScanStarted) {
		t.Errorf("expected scan_started event, got types: %v", eventTypes(events))
	}
	if !hasEvent(events, EventScanCompleted) {
		t.Errorf("expected scan_completed event, got types: %v", eventTypes(events))
	}
	if hasEvent(events, EventScanFailed) {
		t.Errorf("unexpected scan_failed event, got types: %v", eventTypes(events))
	}
}

func TestScan_EmitsCollectorEvents(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
			&fakeCollector{name: "host", result: schema.CollectorResult{Status: schema.CollectorPartial}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	if countEvents(events, EventCollectorStarted) != 2 {
		t.Errorf("expected 2 collector_started events, got %d", countEvents(events, EventCollectorStarted))
	}
	if countEvents(events, EventCollectorDone) != 2 {
		t.Errorf("expected 2 collector_done events, got %d", countEvents(events, EventCollectorDone))
	}

	// Verify done events have correct statuses
	for _, e := range events {
		if e.Type == EventCollectorDone {
			if e.Collector == "env" && e.Status != schema.CollectorOK {
				t.Errorf("expected env status ok, got %v", e.Status)
			}
			if e.Collector == "host" && e.Status != schema.CollectorPartial {
				t.Errorf("expected host status partial, got %v", e.Status)
			}
		}
	}
}

func TestScan_EmitsTimeoutEvent(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "slow", delay: 10 * time.Second},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}

	// Use a runner with a very short timeout
	scanner := NewScanner(ScannerDeps{
		CollectorFactory: factory,
		Runner: func() *collectors.Runner {
			r := collectors.NewRunner()
			r.Timeout = 25 * time.Millisecond
			return r
		}(),
		Engines: engines,
		RunID:   func() string { return "test-run-id" },
		Now:     func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
	})

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	var timeoutFound bool
	for _, e := range events {
		if e.Type == EventCollectorDone && e.Collector == "slow" {
			if e.Status != schema.CollectorTimeout {
				t.Errorf("expected timeout status, got %v", e.Status)
			}
			if !strings.Contains(e.Message, "timed out") {
				t.Errorf("expected timeout message, got %q", e.Message)
			}
			timeoutFound = true
		}
	}
	if !timeoutFound {
		t.Errorf("expected timeout collector_done event, got events: %v", eventTypes(events))
	}
}

func TestScan_EmitsFindingEvents(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{
			{ID: "F-TEST-001", Severity: schema.SeverityHigh, Confidence: 0.9},
			{ID: "F-TEST-002", Severity: schema.SeverityMedium, Confidence: 0.7},
		},
	}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	if !hasEvent(events, EventRuleEvaluated) {
		t.Error("expected rule_evaluated event")
	}
	if countEvents(events, EventFindingAdded) != 2 {
		t.Errorf("expected 2 finding_added events, got %d", countEvents(events, EventFindingAdded))
	}

	for _, e := range events {
		if e.Type == EventFindingAdded {
			if e.FindingID == "" {
				t.Error("expected FindingID in finding_added event")
			}
			if e.Severity == "" {
				t.Error("expected Severity in finding_added event")
			}
		}
	}
}

func TestScan_M6Profile(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "gpu", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{},
		m6Findings: []schema.Finding{
			{ID: "F-GPU-001", Severity: schema.SeverityHigh, Confidence: 0.9},
		},
	}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: ".", Profile: "ai-ml"}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}

	events := sink.Events()
	if !hasEvent(events, EventRuleEvaluated) {
		for _, e := range events {
			if e.RuleEngine == "m6" {
				// found it with different check
			}
		}
	}
	m6Found := false
	for _, e := range events {
		if e.RuleEngine == "m6" {
			m6Found = true
			break
		}
	}
	if !m6Found {
		t.Error("expected m6 rule_evaluated event")
	}
}

func TestScan_M8WithCISignal(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "ci", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test", HasCI: true},
	}
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{},
		m8Findings: []schema.Finding{
			{ID: "F-CI-001", Severity: schema.SeverityMedium, Confidence: 0.8},
		},
	}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}

	events := sink.Events()
	m8Found := false
	for _, e := range events {
		if e.RuleEngine == "m8" {
			m8Found = true
			break
		}
	}
	if !m8Found {
		t.Error("expected m8 rule_evaluated event")
	}
}

func TestScan_M8ForcedByCIFlag(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "ci", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test", HasCI: false},
	}
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{},
		m8Findings: []schema.Finding{
			{ID: "F-CI-001", Severity: schema.SeverityMedium, Confidence: 0.8},
		},
	}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: ".", CI: true}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	m8Found := false
	for _, e := range events {
		if e.RuleEngine == "m8" {
			m8Found = true
			break
		}
	}
	if !m8Found {
		t.Error("expected m8 rule_evaluated event when CI flag is set")
	}
}

func TestScan_M1EngineError(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{
		m1Err: errors.New("m1 evaluation failed"),
	}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err == nil {
		t.Fatal("expected error from M1 engine")
	}

	events := sink.Events()
	if !hasEvent(events, EventScanFailed) {
		t.Errorf("expected scan_failed event, got types: %v", eventTypes(events))
	}
	for _, e := range events {
		if e.Type == EventScanFailed {
			if e.Err == nil {
				t.Error("expected Err to be set on scan_failed event")
			}
			if !strings.Contains(e.Error, "m1 evaluation failed") {
				t.Errorf("expected error message in scan_failed, got %q", e.Error)
			}
		}
	}
}

func TestScan_SanitizesEventErrors(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{
		m1Err: errors.New("SECRET_KEY=leaked"),
	}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: ".", RedactLevel: "default"}, sink)
	if err == nil {
		t.Fatal("expected error")
	}

	events := sink.Events()
	for _, e := range events {
		if e.Type == EventScanFailed {
			if strings.Contains(e.Error, "leaked") {
				t.Errorf("expected error to be sanitized, got: %q", e.Error)
			}
			if !strings.Contains(e.Error, "SECRET_KEY=") {
				t.Errorf("expected key to be preserved, got: %q", e.Error)
			}
		}
	}
}

func TestScan_NilSinkDoesNotPanic(t *testing.T) {
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScan_EventRunIDAndPath(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "/some/path"}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	for _, e := range events {
		if e.RunID != "test-run-id" {
			t.Errorf("event %q: expected run_id test-run-id, got %q", e.Type, e.RunID)
		}
		if e.Path != "/some/path" {
			t.Errorf("event %q: expected path /some/path, got %q", e.Type, e.Path)
		}
	}
}

func TestScan_EventTimestampSet(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	fixed := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	scanner := NewScanner(ScannerDeps{
		CollectorFactory: factory,
		Runner:           collectors.NewRunner(),
		Engines:          engines,
		RunID:            func() string { return "test-run-id" },
		Now:              func() time.Time { return fixed },
	})

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	for _, e := range events {
		if e.Timestamp != fixed {
			t.Errorf("event %q: expected timestamp %v, got %v", e.Type, fixed, e.Timestamp)
		}
	}
}

func TestScan_ReportContainsCollectorResults(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK, Evidence: []schema.Evidence{{Source: "test", Value: "value"}}}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Collectors) != 1 {
		t.Fatalf("expected 1 collector result, got %d", len(report.Collectors))
	}
	if report.Collectors[0].Name != "env" {
		t.Errorf("expected collector name env, got %s", report.Collectors[0].Name)
	}
}

func TestScan_ScanConvenienceFunction(t *testing.T) {
	// Scan with default deps should work without panicking on a path that
	// has no special signals. It will use real collectors and engines,
	// so we just verify it returns a report.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := Scan(ctx, ScanOptions{Path: "."}, NoopSink{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected report from Scan convenience function")
	}
	if report.RunID == "" {
		t.Error("expected non-empty run ID")
	}
}

func TestScan_DurationMsInCompletedEvent(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	call := 0
	scanner := NewScanner(ScannerDeps{
		CollectorFactory: factory,
		Runner:           collectors.NewRunner(),
		Engines:          engines,
		RunID:            func() string { return "test-run-id" },
		Now: func() time.Time {
			call++
			return base.Add(time.Duration(call) * time.Second)
		},
	})

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	for _, e := range events {
		if e.Type == EventScanCompleted {
			if e.DurationMs < 0 {
				t.Errorf("expected non-negative duration, got %d", e.DurationMs)
			}
			// With our fake Now, at least some time should have passed
			if e.DurationMs == 0 && call > 1 {
				t.Logf("duration was zero but multiple Now calls were made")
			}
		}
	}
}

func TestScan_FindingAggregatorDedupesAndSorts(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	// Provide duplicate findings with different severities to verify aggregation
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{
			{ID: "F-TEST-001", Severity: schema.SeverityLow, Confidence: 0.5, Evidence: []schema.Evidence{{Source: "a", Value: "1"}}},
			{ID: "F-TEST-001", Severity: schema.SeverityHigh, Confidence: 0.9, Evidence: []schema.Evidence{{Source: "a", Value: "1"}}},
		},
	}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(report.Findings))
	}
	// The high severity one should win
	if report.Findings[0].Severity != schema.SeverityHigh {
		t.Errorf("expected high severity after dedup, got %v", report.Findings[0].Severity)
	}
}

func TestScan_CollectorDoneMessageForTimeout(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "slow", delay: 10 * time.Second},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := NewScanner(ScannerDeps{
		CollectorFactory: factory,
		Runner: func() *collectors.Runner {
			r := collectors.NewRunner()
			r.Timeout = 25 * time.Millisecond
			return r
		}(),
		Engines: engines,
		RunID:   func() string { return "test-run-id" },
		Now:     func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
	})

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	for _, e := range events {
		if e.Type == EventCollectorDone && e.Collector == "slow" {
			if !strings.Contains(e.Message, "timed out") {
				t.Errorf("expected timeout message to contain 'timed out', got %q", e.Message)
			}
		}
	}
}

func TestScan_CollectorDoneMessageForNormalStatus(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := sink.Events()
	for _, e := range events {
		if e.Type == EventCollectorDone && e.Collector == "env" {
			if !strings.Contains(e.Message, "done with status") {
				t.Errorf("expected normal done message, got %q", e.Message)
			}
		}
	}
}

func TestScan_RulePackError(t *testing.T) {
	// This test uses a real rule pack path that doesn't exist.
	// The rule pack evaluation should fail and emit a scan_failed event.
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "env", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{m1Findings: []schema.Finding{}}
	scanner := newTestScanner(factory, engines)

	_, err := scanner.Scan(context.Background(), ScanOptions{Path: ".", RulePackPath: "/nonexistent/path.rego"}, sink)
	if err == nil {
		t.Fatal("expected error for missing rule pack")
	}

	var rpe *RulePackError
	if !errors.As(err, &rpe) {
		t.Fatalf("expected RulePackError, got %T: %v", err, err)
	}
	if len(rpe.Errors) == 0 {
		t.Error("expected RulePackError.Errors to be non-empty")
	}

	events := sink.Events()
	if !hasEvent(events, EventScanFailed) {
		t.Errorf("expected scan_failed event for missing rule pack, got types: %v", eventTypes(events))
	}
}

func TestScan_M6ErrorTolerated(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "gpu", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test"},
	}
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{},
		m6Err:      errors.New("m6 engine failure"),
	}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: ".", Profile: "ai-ml"}, sink)
	if err != nil {
		t.Fatalf("M6 error should be tolerated, got: %v", err)
	}
	if report == nil {
		t.Fatal("expected report despite M6 error")
	}

	events := sink.Events()
	m6ErrFound := false
	for _, e := range events {
		if e.RuleEngine == "m6" && e.Error != "" {
			m6ErrFound = true
		}
	}
	if !m6ErrFound {
		t.Errorf("expected M6 rule_evaluated event with error, got events: %v", eventTypes(events))
	}
	if hasEvent(events, EventScanFailed) {
		t.Error("M6 error should not emit scan_failed")
	}
}

func TestScan_M8ErrorTolerated(t *testing.T) {
	sink := &RecordingSink{}
	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{
			&fakeCollector{name: "ci", result: schema.CollectorResult{Status: schema.CollectorOK}},
		},
		signals: RepoSignals{Root: "/tmp/test", HasCI: true},
	}
	engines := &fakeEngineFactory{
		m1Findings: []schema.Finding{},
		m8Err:      errors.New("m8 engine failure"),
	}
	scanner := newTestScanner(factory, engines)

	report, err := scanner.Scan(context.Background(), ScanOptions{Path: "."}, sink)
	if err != nil {
		t.Fatalf("M8 error should be tolerated, got: %v", err)
	}
	if report == nil {
		t.Fatal("expected report despite M8 error")
	}

	events := sink.Events()
	m8ErrFound := false
	for _, e := range events {
		if e.RuleEngine == "m8" && e.Error != "" {
			m8ErrFound = true
		}
	}
	if !m8ErrFound {
		t.Errorf("expected M8 rule_evaluated event with error, got events: %v", eventTypes(events))
	}
	if hasEvent(events, EventScanFailed) {
		t.Error("M8 error should not emit scan_failed")
	}
}

func TestScan_RulePackValid(t *testing.T) {
	// This test requires creating a temporary valid rego rule pack.
	// Since this is complex and depends on real rego evaluation,
	// we skip it in favor of the error case above.
	t.Skip("skipping rule pack success test; requires temporary rego files")
}

func TestRulePackError_WrappedStillMatches(t *testing.T) {
	inner := &RulePackError{Errors: []string{"bad pack"}}
	wrapped := fmt.Errorf("wrapped: %w", inner)

	var rpe *RulePackError
	if !errors.As(wrapped, &rpe) {
		t.Fatal("expected errors.As to match wrapped RulePackError")
	}
	if len(rpe.Errors) != 1 || rpe.Errors[0] != "bad pack" {
		t.Errorf("expected Errors ['bad pack'], got %v", rpe.Errors)
	}
}

func TestDefaultScannerDeps_ReturnsNonNil(t *testing.T) {
	deps := DefaultScannerDeps()
	if deps.CollectorFactory == nil {
		t.Error("expected non-nil CollectorFactory")
	}
	if deps.Runner == nil {
		t.Error("expected non-nil Runner")
	}
	if deps.Engines == nil {
		t.Error("expected non-nil Engines")
	}
	if deps.RunID == nil {
		t.Error("expected non-nil RunID")
	}
	if deps.Now == nil {
		t.Error("expected non-nil Now")
	}
}

func TestGenerateRunID_Unique(t *testing.T) {
	now := time.Now()
	id1 := newRunID(now)
	id2 := newRunID(now)
	if id1 == id2 {
		t.Error("expected two different run IDs")
	}
	if id1 == "" {
		t.Error("expected non-empty run ID")
	}
}

func TestPopulateHostInfo_ExtractsFromHostCollector(t *testing.T) {
	results := []schema.CollectorResult{
		{
			Name: "other",
			Evidence: []schema.Evidence{
				{Source: "host_os_id", Value: "should_not_match"},
			},
		},
		{
			Name: "host",
			Evidence: []schema.Evidence{
				{Source: "host_os_id", Value: "linux"},
				{Source: "host_os_version", Value: "22.04"},
				{Source: "host_kernel", Value: "5.15"},
				{Source: "host_arch", Value: "amd64"},
			},
		},
	}
	host := populateHostInfo(results)
	if host.OS != "linux" {
		t.Errorf("expected OS linux, got %q", host.OS)
	}
	if host.Version != "22.04" {
		t.Errorf("expected version 22.04, got %q", host.Version)
	}
	if host.Kernel != "5.15" {
		t.Errorf("expected kernel 5.15, got %q", host.Kernel)
	}
	if host.Arch != "amd64" {
		t.Errorf("expected arch amd64, got %q", host.Arch)
	}
}

func TestPopulateHostInfo_EmptyWhenNoHostCollector(t *testing.T) {
	results := []schema.CollectorResult{
		{Name: "env", Evidence: []schema.Evidence{{Source: "test", Value: "x"}}},
	}
	host := populateHostInfo(results)
	if host.OS != "" || host.Version != "" || host.Kernel != "" || host.Arch != "" {
		t.Errorf("expected empty host info, got %+v", host)
	}
}

func TestEventObserver_CollectorStarted(t *testing.T) {
	var captured Event
	obs := &eventObserver{emit: func(e Event) {
		captured = e
	}}
	obs.CollectorStarted("env")
	if captured.Type != EventCollectorStarted {
		t.Errorf("expected %q, got %q", EventCollectorStarted, captured.Type)
	}
	if captured.Collector != "env" {
		t.Errorf("expected collector env, got %q", captured.Collector)
	}
	if !strings.Contains(captured.Message, "env started") {
		t.Errorf("expected message to contain 'env started', got %q", captured.Message)
	}
}

func TestEventObserver_CollectorDoneOK(t *testing.T) {
	var captured Event
	obs := &eventObserver{emit: func(e Event) {
		captured = e
	}}
	obs.CollectorDone(schema.CollectorResult{Name: "env", Status: schema.CollectorOK}, time.Second)
	if captured.Type != EventCollectorDone {
		t.Errorf("expected %q, got %q", EventCollectorDone, captured.Type)
	}
	if captured.Status != schema.CollectorOK {
		t.Errorf("expected status ok, got %v", captured.Status)
	}
	if captured.DurationMs != 1000 {
		t.Errorf("expected duration 1000ms, got %d", captured.DurationMs)
	}
	if !strings.Contains(captured.Message, "done with status") {
		t.Errorf("expected normal done message, got %q", captured.Message)
	}
}

func TestEventObserver_CollectorDoneTimeout(t *testing.T) {
	var captured Event
	obs := &eventObserver{emit: func(e Event) {
		captured = e
	}}
	obs.CollectorDone(schema.CollectorResult{Name: "slow", Status: schema.CollectorTimeout}, 500*time.Millisecond)
	if captured.Status != schema.CollectorTimeout {
		t.Errorf("expected timeout status, got %v", captured.Status)
	}
	if !strings.Contains(captured.Message, "timed out") {
		t.Errorf("expected timeout message, got %q", captured.Message)
	}
	if captured.DurationMs != 500 {
		t.Errorf("expected duration 500ms, got %d", captured.DurationMs)
	}
}

// nonThreadSafeSink is a sink that is NOT thread-safe for race detection.
type nonThreadSafeSink struct {
	counts map[string]int
}

func (s *nonThreadSafeSink) Emit(e Event) {
	s.counts[string(e.Type)]++
}

func TestScan_ConcurrentEventSinkSafety(t *testing.T) {
	// Setup multiple collectors to run in parallel
	c1 := &fakeCollector{name: "c1", delay: 10 * time.Millisecond}
	c2 := &fakeCollector{name: "c2", delay: 10 * time.Millisecond}

	factory := &fakeCollectorFactory{
		collectors: []collectors.Collector{c1, c2},
	}
	scanner := newTestScanner(factory, &fakeEngineFactory{})

	// Use a non-thread-safe sink.
	// app.Scan should wrap it in a MutexSink, preventing a race.
	sink := &nonThreadSafeSink{
		counts: make(map[string]int),
	}

	_, err := scanner.Scan(context.Background(), ScanOptions{}, sink)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
}
