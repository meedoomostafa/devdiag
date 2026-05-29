package trace

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/redact"
)

func TestRedactResult_RedactsEventError(t *testing.T) {
	eng := redact.NewEngine(redact.LevelDefault)
	res := &Result{
		Events: []Event{
			{Syscall: "open", Error: "API_KEY=secret"},
		},
	}
	redacted := RedactResult(res, eng)
	if strings.Contains(redacted.Events[0].Error, "secret") {
		t.Errorf("Event.Error not redacted: %s", redacted.Events[0].Error)
	}
}

func TestRedactResult_RedactsCapabilityEvidence(t *testing.T) {
	eng := redact.NewEngine(redact.LevelDefault)
	res := &Result{
		CapabilityEvidence: []TraceEvidence{
			{Source: "API_KEY", Value: "API_KEY=secret"},
		},
	}
	redacted := RedactResult(res, eng)
	if strings.Contains(redacted.CapabilityEvidence[0].Value, "secret") {
		t.Errorf("CapabilityEvidence.Value not redacted: %s", redacted.CapabilityEvidence[0].Value)
	}
}

func TestRedactResult_RedactsUnavailableReason(t *testing.T) {
	eng := redact.NewEngine(redact.LevelDefault)
	res := &Result{
		UnavailableReason: "API_KEY=secret",
	}
	redacted := RedactResult(res, eng)
	if strings.Contains(redacted.UnavailableReason, "secret") {
		t.Errorf("UnavailableReason not redacted: %s", redacted.UnavailableReason)
	}
}
