package app

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestEventSinkFunc_EmitsEvent(t *testing.T) {
	var received Event
	sink := EventSinkFunc(func(e Event) {
		received = e
	})

	sink.Emit(Event{Type: EventScanStarted, Message: "test"})

	if received.Type != EventScanStarted {
		t.Errorf("expected event type %q, got %q", EventScanStarted, received.Type)
	}
	if received.Message != "test" {
		t.Errorf("expected message %q, got %q", "test", received.Message)
	}
}

func TestNoopSink_DiscardsEvents(t *testing.T) {
	sink := NoopSink{}
	// Should not panic or block
	sink.Emit(Event{Type: EventScanStarted})
	sink.Emit(Event{Type: EventScanCompleted})
}

func TestChannelSink_EmitsEvent(t *testing.T) {
	ch := make(chan Event, 2)
	sink := &ChannelSink{C: ch}

	sink.Emit(Event{Type: EventScanStarted, Message: "start"})
	sink.Emit(Event{Type: EventScanCompleted, Message: "done"})

	select {
	case e := <-ch:
		if e.Type != EventScanStarted {
			t.Errorf("expected scan_started, got %q", e.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first event")
	}

	select {
	case e := <-ch:
		if e.Type != EventScanCompleted {
			t.Errorf("expected scan_completed, got %q", e.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second event")
	}
}

func TestChannelSink_NonBlockingWhenFull(t *testing.T) {
	ch := make(chan Event, 0)
	sink := &ChannelSink{C: ch}

	// This should not block even though channel is unbuffered and no reader
	done := make(chan struct{})
	go func() {
		sink.Emit(Event{Type: EventScanStarted})
		close(done)
	}()

	select {
	case <-done:
		// expected: Emit dropped the event without blocking
	case <-time.After(time.Second):
		t.Fatal("Emit blocked on full channel")
	}
}

func TestRecordingSink_RecordsEvents(t *testing.T) {
	sink := &RecordingSink{}

	sink.Emit(Event{Type: EventScanStarted})
	sink.Emit(Event{Type: EventCollectorStarted, Collector: "env"})
	sink.Emit(Event{Type: EventCollectorDone, Collector: "env", Status: schema.CollectorOK})
	sink.Emit(Event{Type: EventScanCompleted})

	events := sink.Events()
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	types := []EventType{events[0].Type, events[1].Type, events[2].Type, events[3].Type}
	expected := []EventType{EventScanStarted, EventCollectorStarted, EventCollectorDone, EventScanCompleted}
	for i, want := range expected {
		if types[i] != want {
			t.Errorf("event[%d]: expected type %q, got %q", i, want, types[i])
		}
	}

	if events[1].Collector != "env" {
		t.Errorf("expected collector env, got %q", events[1].Collector)
	}
	if events[2].Status != schema.CollectorOK {
		t.Errorf("expected status ok, got %v", events[2].Status)
	}
}

func TestRecordingSink_CopyIsolation(t *testing.T) {
	sink := &RecordingSink{}
	sink.Emit(Event{Type: EventScanStarted})

	a := sink.Events()
	b := sink.Events()

	if len(a) != 1 || len(b) != 1 {
		t.Fatal("expected one event in each copy")
	}

	// Mutating a should not affect b
	a[0].Type = EventScanFailed
	if b[0].Type != EventScanStarted {
		t.Error("mutating copy a affected copy b")
	}
}

func TestMutexSink_ConcurrencySafe(t *testing.T) {
	inner := &RecordingSink{}
	sink := NewMutexSink(inner)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink.Emit(Event{Type: EventScanStarted})
		}()
	}
	wg.Wait()

	if len(inner.Events()) != 100 {
		t.Errorf("expected 100 events, got %d", len(inner.Events()))
	}
}

func TestMutexSink_NilFallback(t *testing.T) {
	sink := NewMutexSink(nil)
	// Should not panic
	sink.Emit(Event{Type: EventScanStarted})
}

func TestSanitizeString_RedactsEnvValues(t *testing.T) {
	input := "DB_PASSWORD=secret123 API_TOKEN=abc123"
	got := sanitizeString(input, "default")
	if strings.Contains(got, "secret123") {
		t.Errorf("expected secret to be redacted, got: %s", got)
	}
	if strings.Contains(got, "abc123") {
		t.Errorf("expected token to be redacted, got: %s", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=") {
		t.Errorf("expected key to be preserved, got: %s", got)
	}
}

func TestSanitizeString_RedactsCLISecrets(t *testing.T) {
	input := "--password=secret --token abc123"
	got := sanitizeString(input, "default")
	if strings.Contains(got, "secret") {
		t.Errorf("expected password to be redacted, got: %s", got)
	}
	if strings.Contains(got, "abc123") {
		t.Errorf("expected token to be redacted, got: %s", got)
	}
}

func TestSanitizeString_EmptyLevelDefaults(t *testing.T) {
	input := "SECRET_KEY=hidden"
	got := sanitizeString(input, "")
	if strings.Contains(got, "hidden") {
		t.Errorf("expected default redaction to apply, got: %s", got)
	}
}

func TestSanitizeString_EmptyString(t *testing.T) {
	got := sanitizeString("", "default")
	if got != "" {
		t.Errorf("expected empty string, got: %q", got)
	}
}

func TestSanitizeString_OffPreservesContent(t *testing.T) {
	input := "password=secret"
	got := sanitizeString(input, "off")
	if got != input {
		t.Errorf("expected off to preserve content, got: %q", got)
	}
}
