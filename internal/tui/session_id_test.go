package tui

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestModel_SessionID_IgnoresStaleMessages(t *testing.T) {
	m := Model{sessionID: 1}
	
	// 1. Setup Session 2 (Current)
	sess2 := &scanSession{
		id:   2,
		ch:   make(chan app.Event, 10),
		done: make(chan struct{}),
	}
	m.session = sess2
	m.sessionID = 2
	m.scanning = true
	
	// 2. Send scanEventMsg from session 1 (Stale)
	m2, _ := m.Update(scanEventMsg{sessionID: 1, event: app.Event{Message: "stale"}})
	m = m2.(Model)
	if len(m.events) != 0 {
		t.Error("Expected stale event to be ignored")
	}

	// 3. Send scanEventMsg from session 2 (Current)
	m3, _ := m.Update(scanEventMsg{sessionID: 2, event: app.Event{Message: "current"}})
	m = m3.(Model)
	if len(m.events) != 1 || m.events[0].Message != "current" {
		t.Errorf("Expected current event to be processed, got %d events", len(m.events))
	}

	// 4. Send scanDoneMsg from session 1 (Stale)
	report1 := &schema.Report{RunID: "stale"}
	m4, _ := m.Update(scanDoneMsg{sessionID: 1, report: report1})
	m = m4.(Model)
	if m.report != nil || !m.scanning {
		t.Error("Expected stale scanDoneMsg to be ignored")
	}

	// 5. Send scanDoneMsg from session 2 (Current)
	report2 := &schema.Report{RunID: "current"}
	m5, _ := m.Update(scanDoneMsg{sessionID: 2, report: report2})
	m = m5.(Model)
	if m.report == nil || m.report.RunID != "current" || m.scanning {
		t.Error("Expected current scanDoneMsg to be processed")
	}

	// 6. Reset for Error Test
	m.scanning = true
	m.scanErr = nil
	
	// 7. Send scanErrMsg from session 1 (Stale)
	m6, _ := m.Update(scanDoneMsg{sessionID: 1, err: someError("stale")})
	m = m6.(Model)
	if m.scanErr != nil {
		t.Error("Expected stale error to be ignored")
	}

	// 8. Send scanErrMsg from session 2 (Current)
	m7, _ := m.Update(scanDoneMsg{sessionID: 2, err: someError("current")})
	m = m7.(Model)
	if m.scanErr == nil || m.scanErr.Error() != "current" {
		t.Error("Expected current error to be processed")
	}
}
