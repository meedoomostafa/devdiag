package app

import (
	"sync"
	"time"

	"github.com/meedoomostafa/devdiag/internal/redact"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// EventType represents a typed scan lifecycle event.
type EventType string

const (
	EventScanStarted      EventType = "scan_started"
	EventCollectorStarted EventType = "collector_started"
	EventCollectorDone    EventType = "collector_done"
	EventRuleEvaluated    EventType = "rule_evaluated"
	EventFindingAdded     EventType = "finding_added"
	EventScanCompleted    EventType = "scan_completed"
	EventScanFailed       EventType = "scan_failed"
)

// Event is a single progress event in the scan lifecycle.
// Err is internal-only and must not be serialized or exposed to TUI text.
type Event struct {
	Type       EventType              `json:"type"`
	Timestamp  time.Time              `json:"timestamp"`
	RunID      string                 `json:"run_id,omitempty"`
	Path       string                 `json:"path,omitempty"`
	Domain     string                 `json:"domain,omitempty"`
	Collector  string                 `json:"collector,omitempty"`
	Status     schema.CollectorStatus `json:"status,omitempty"`
	RuleEngine string                 `json:"rule_engine,omitempty"`
	CheckID    string                 `json:"check_id,omitempty"`
	FindingID  string                 `json:"finding_id,omitempty"`
	Severity   schema.Severity        `json:"severity,omitempty"`
	Confidence float64                `json:"confidence,omitempty"`
	DurationMs int64                  `json:"duration_ms,omitempty"`
	Message    string                 `json:"message,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Err        error                  `json:"-"`
}

// EventSink receives emitted events.
// Implementations must be concurrency-safe because collectors run concurrently.
type EventSink interface {
	Emit(Event)
}

// EventSinkFunc adapts a function to EventSink.
type EventSinkFunc func(Event)

// Emit implements EventSink.
func (f EventSinkFunc) Emit(e Event) { f(e) }

// NoopSink discards all events.
type NoopSink struct{}

// Emit implements EventSink.
func (NoopSink) Emit(Event) {}

// ChannelSink sends events on a channel.
type ChannelSink struct {
	C chan Event
}

// Emit implements EventSink.
func (s *ChannelSink) Emit(e Event) {
	select {
	case s.C <- e:
	default:
	}
}

// RecordingSink records all events for later inspection.
type RecordingSink struct {
	mu     sync.Mutex
	events []Event
}

// Emit implements EventSink.
func (s *RecordingSink) Emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// Events returns a copy of recorded events.
func (s *RecordingSink) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

// MutexSink wraps another sink with a mutex for concurrency safety.
type MutexSink struct {
	mu   sync.Mutex
	sink EventSink
}

// NewMutexSink returns a concurrency-safe wrapper around the given sink.
func NewMutexSink(sink EventSink) EventSink {
	if sink == nil {
		return NoopSink{}
	}
	return &MutexSink{sink: sink}
}

// Emit implements EventSink.
func (s *MutexSink) Emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sink.Emit(e)
}

// sanitizeString redacts sensitive content from event strings before emission.
func sanitizeString(s string, level string) string {
	if s == "" {
		return ""
	}
	l := redact.Level(level)
	if l == "" {
		l = redact.LevelDefault
	}
	engine := redact.NewEngine(l)
	return engine.RedactString(s, "event")
}
