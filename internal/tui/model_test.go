package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestConfidenceLabel(t *testing.T) {
	tests := []struct {
		confidence float64
		want       string
	}{
		{0.90, "high"},
		{0.85, "high"},
		{0.84, "medium"},
		{0.60, "medium"},
		{0.59, "low"},
		{0.10, "low"},
		{0.0, "low"},
	}
	for _, tt := range tests {
		got := confidenceLabel(tt.confidence)
		if got != tt.want {
			t.Errorf("confidenceLabel(%.2f) = %q, want %q", tt.confidence, got, tt.want)
		}
	}
}

func TestDeriveDomain_FromID(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"F-CI-RUNTIME-001", "ci"},
		{"F-ENV-SECRET-001", "env"},
		{"F-PORT-EXPOSE-001", "network"},
		{"F-SECURITY-PERM-001", "security"},
		{"F-CONTAINER-IMAGE-001", "containers"},
		{"F-DOCKER-FILE-001", "containers"},
		{"F-PODMAN-SOCK-001", "containers"},
		{"F-GPU-CUDA-001", "gpu"},
		{"F-CACHE-STALE-001", "cache"},
		{"F-HOST-OS-001", "host"},
		{"F-PERMISSION-ROOT-001", "permissions"},
		{"F-GIT-LEAK-001", "git"},
		{"F-CONFIG-ERROR-001", "config"},
		{"F-RUNTIME-DECL-001", "runtime"},
		{"F-UNKNOWN-001", "general"},
	}
	for _, tt := range tests {
		f := schema.Finding{ID: tt.id}
		got := deriveDomain(f)
		if got != tt.want {
			t.Errorf("deriveDomain(ID=%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestDeriveDomain_FromLayers(t *testing.T) {
	f := schema.Finding{ID: "F-OTHER-001", Layers: []string{"ci", "local"}}
	got := deriveDomain(f)
	if got != "ci" {
		t.Errorf("deriveDomain from layers = %q, want ci", got)
	}
}

func TestDeriveBlastRadius(t *testing.T) {
	tests := []struct {
		severity schema.Severity
		want     string
	}{
		{schema.SeverityCritical, "high"},
		{schema.SeverityHigh, "high"},
		{schema.SeverityMedium, "medium"},
		{schema.SeverityLow, "low"},
		{schema.SeverityInfo, "low"},
	}
	for _, tt := range tests {
		f := schema.Finding{Severity: tt.severity}
		got := deriveBlastRadius(f)
		if got != tt.want {
			t.Errorf("deriveBlastRadius(%s) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestDeriveMutationRisk(t *testing.T) {
	tests := []struct {
		name    string
		finding schema.Finding
		want    string
	}{
		{
			name: "destructive hint",
			finding: schema.Finding{
				FixHints: []string{"This is a destructive operation"},
				Severity: schema.SeverityHigh,
			},
			want: "high",
		},
		{
			name: "safe hint",
			finding: schema.Finding{
				FixHints: []string{"Safe to restart the service"},
				Severity: schema.SeverityHigh,
			},
			want: "low",
		},
		{
			name: "default high severity",
			finding: schema.Finding{
				Severity: schema.SeverityHigh,
			},
			want: "medium",
		},
		{
			name: "default low severity",
			finding: schema.Finding{
				Severity: schema.SeverityInfo,
			},
			want: "low",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveMutationRisk(tt.finding)
			if got != tt.want {
				t.Errorf("deriveMutationRisk() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeriveReasoning(t *testing.T) {
	f := schema.Finding{
		Symptom:      "Port 8080 is exposed",
		LikelyCauses: []string{"Default config left exposed"},
	}
	got := deriveReasoning(f)
	if len(got) != 2 {
		t.Fatalf("expected 2 reasoning lines, got %d", len(got))
	}
	if got[0] != f.Symptom {
		t.Errorf("reasoning[0] = %q, want %q", got[0], f.Symptom)
	}
}

func TestDeriveReasoning_Fallback(t *testing.T) {
	f := schema.Finding{}
	got := deriveReasoning(f)
	if len(got) != 1 || got[0] != "Derived from evidence and rule evaluation." {
		t.Errorf("fallback reasoning = %v", got)
	}
}

func TestBuildInspectFindings(t *testing.T) {
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-CI-001", Severity: schema.SeverityMedium, Confidence: 0.75, Title: "CI drift"},
			{ID: "F-ENV-001", Severity: schema.SeverityHigh, Confidence: 0.90, Title: "Secret exposed"},
		},
	}
	findings := BuildInspectFindings(report)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// BuildInspectFindings preserves report order; sorting is done by the model.
	var foundHigh, foundMedium bool
	for _, f := range findings {
		if f.Finding.ID == "F-ENV-001" {
			foundHigh = true
			if f.ConfidenceLabel != "high" {
				t.Errorf("F-ENV-001 confidence label = %q, want high", f.ConfidenceLabel)
			}
			if f.Domain != "env" {
				t.Errorf("F-ENV-001 domain = %q, want env", f.Domain)
			}
		}
		if f.Finding.ID == "F-CI-001" {
			foundMedium = true
			if f.ConfidenceLabel != "medium" {
				t.Errorf("F-CI-001 confidence label = %q, want medium", f.ConfidenceLabel)
			}
			if f.Domain != "ci" {
				t.Errorf("F-CI-001 domain = %q, want ci", f.Domain)
			}
		}
	}
	if !foundHigh {
		t.Error("missing F-ENV-001 finding")
	}
	if !foundMedium {
		t.Error("missing F-CI-001 finding")
	}
}

func TestBuildInspectFindings_NilReport(t *testing.T) {
	findings := BuildInspectFindings(nil)
	if findings != nil {
		t.Error("expected nil for nil report")
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(schema.SeverityCritical) <= severityRank(schema.SeverityHigh) {
		t.Error("critical should rank higher than high")
	}
	if severityRank(schema.SeverityHigh) <= severityRank(schema.SeverityInfo) {
		t.Error("high should rank higher than info")
	}
}

func TestSortFindingsBySeverity_Stable(t *testing.T) {
	findings := []InspectFinding{
		{Finding: schema.Finding{Severity: schema.SeverityMedium, Confidence: 0.5, ID: "A"}},
		{Finding: schema.Finding{Severity: schema.SeverityHigh, Confidence: 0.9, ID: "B"}},
		{Finding: schema.Finding{Severity: schema.SeverityMedium, Confidence: 0.8, ID: "C"}},
	}
	sorted := sortFindingsBySeverity(findings)
	if sorted[0].Finding.ID != "B" {
		t.Errorf("first = %q, want B", sorted[0].Finding.ID)
	}
	if sorted[1].Finding.ID != "C" {
		t.Errorf("second = %q, want C", sorted[1].Finding.ID)
	}
	if sorted[2].Finding.ID != "A" {
		t.Errorf("third = %q, want A", sorted[2].Finding.ID)
	}
}

func TestModel_Navigation(t *testing.T) {
	m := Model{
		filtered: []InspectFinding{
			{Finding: schema.Finding{ID: "A"}},
			{Finding: schema.Finding{ID: "B"}},
			{Finding: schema.Finding{ID: "C"}},
		},
		selected: 0,
	}

	m.nextFinding()
	if m.selected != 1 {
		t.Errorf("next: selected = %d, want 1", m.selected)
	}
	m.nextFinding()
	m.nextFinding()
	if m.selected != 2 {
		t.Errorf("next past end: selected = %d, want 2", m.selected)
	}

	m.prevFinding()
	if m.selected != 1 {
		t.Errorf("prev: selected = %d, want 1", m.selected)
	}
	m.prevFinding()
	m.prevFinding()
	if m.selected != 0 {
		t.Errorf("prev past start: selected = %d, want 0", m.selected)
	}
}

func TestModel_ReRun(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "/tmp"}, nil)
	m.scanning = false
	m.findings = []InspectFinding{{Finding: schema.Finding{ID: "X"}}}
	m.filtered = m.findings

	newM, cmd := m.ReRun()
	if !newM.scanning {
		t.Error("expected scanning=true after ReRun")
	}
	if newM.findings != nil {
		t.Error("expected findings cleared after ReRun")
	}
	if cmd == nil {
		t.Error("expected non-nil cmd after ReRun")
	}
}

func TestModel_EmptyStateViews(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.width = 80
	m.height = 24

	// Error state
	m.scanning = false
	m.scanErr = &app.RulePackError{Errors: []string{"bad pack"}}
	v := m.View()
	if v == "" {
		t.Error("error view should not be empty")
	}

	// Empty findings state
	m.scanErr = nil
	m.findings = nil
	m.filtered = nil
	v = m.View()
	if v == "" {
		t.Error("empty view should not be empty")
	}
}

func TestModel_ProgressViewShowsCollectorSummaryAndPartialStatus(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "/repo"}, nil)
	m.width = 100
	m.height = 30
	m.scanning = true
	m.events = []app.Event{
		{Type: app.EventCollectorStarted, Collector: "env"},
		{Type: app.EventCollectorDone, Collector: "env", Status: schema.CollectorOK},
		{Type: app.EventCollectorStarted, Collector: "compose_status"},
		{Type: app.EventCollectorDone, Collector: "compose_status", Status: schema.CollectorPartial},
		{Type: app.EventCollectorStarted, Collector: "runtime"},
	}

	v := m.View()
	for _, want := range []string{
		"scanning /repo",
		"Collectors: 2 done, 1 running, 1 need review",
		"[ok]     env",
		"[partial] compose_status",
		"[run]    runtime",
	} {
		if !strings.Contains(v, want) {
			t.Fatalf("progress view missing %q:\n%s", want, v)
		}
	}
}

func TestModel_ProgressViewUsesDefaultPath(t *testing.T) {
	m := NewModel(app.ScanOptions{}, nil)
	m.width = 100
	m.height = 30
	m.scanning = true

	v := m.View()
	if !strings.Contains(v, "scanning .") {
		t.Fatalf("progress view should use default path, got:\n%s", v)
	}
}

func TestModel_SpinnerTickOnlySchedulesWhileScanning(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = true

	msg := m.spinner.Tick()
	newM, cmd := m.Update(msg)
	if cmd == nil {
		t.Fatal("expected spinner to keep ticking while scanning")
	}

	stopped := newM.(Model)
	stopped.scanning = false
	_, cmd = stopped.Update(stopped.spinner.Tick())
	if cmd != nil {
		t.Fatal("expected no spinner tick command after scan stops")
	}
}

func TestModel_HelpToggle(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.width = 80
	m.height = 24

	m.scanning = false
	m.findings = []InspectFinding{{Finding: schema.Finding{ID: "X", Title: "Test"}}}
	m.filtered = m.findings

	// Normal view
	normal := m.View()

	// Toggle help
	m.showHelp = true
	help := m.View()

	if normal == help {
		t.Error("help view should differ from normal view")
	}
	if help == "" {
		t.Error("help view should not be empty")
	}
}

func TestModel_KeyQuit(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := m.Update(msg)
	if cmd == nil {
		t.Fatal("expected quit command")
	}
}

func TestModel_KeyToggleVerbose(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	m.findings = []InspectFinding{{Finding: schema.Finding{ID: "X"}}}
	m.filtered = m.findings
	m.verbose = false

	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}}
	newM, _ := m.Update(msg)
	if !newM.(Model).verbose {
		t.Error("expected verbose=true after pressing v")
	}
}

func TestModel_KeyToggleHiddenFindings(t *testing.T) {
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-ENV-001", Title: "Env issue", Severity: schema.SeverityMedium},
			{ID: "F-RUNTIME-DECL-001", Title: "Runtime declaration", Severity: schema.SeverityInfo},
		},
	}
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	m = m.applyVisibility(report)
	if len(m.filtered) != 1 {
		t.Fatalf("default TUI visibility = %d findings, want 1", len(m.filtered))
	}
	if m.hiddenCount != 1 {
		t.Fatalf("hidden count = %d, want 1", m.hiddenCount)
	}

	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}}
	newM, _ := m.Update(msg)
	visible := newM.(Model)
	if !visible.showHidden {
		t.Fatal("expected hidden findings to be visible after pressing h")
	}
	if len(visible.filtered) != 2 {
		t.Fatalf("after h filtered findings = %d, want 2", len(visible.filtered))
	}
	if visible.Report() == nil || len(visible.Report().Findings) != 2 {
		t.Fatalf("Report should reflect current hidden visibility, got %#v", visible.Report())
	}
}

func TestModel_FilterMode(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	m.findings = []InspectFinding{
		{Finding: schema.Finding{ID: "F-CI-001", Title: "CI drift", Severity: schema.SeverityMedium}},
		{Finding: schema.Finding{ID: "F-ENV-001", Title: "Secret leak", Severity: schema.SeverityHigh}},
	}
	m.filtered = m.findings

	// Enter filter mode
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}}
	newM, _ := m.Update(msg)
	if !newM.(Model).filtering {
		t.Error("expected filtering=true after pressing /")
	}

	// Type filter text
	newM, _ = newM.(Model).Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'C'}})
	newM, _ = newM.(Model).Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'I'}})

	// Confirm filter
	newM, _ = newM.(Model).Update(tea.KeyMsg{Type: tea.KeyEnter})
	filtered := newM.(Model).filtered
	if len(filtered) != 1 || filtered[0].Finding.ID != "F-CI-001" {
		t.Errorf("filter result = %v, want 1 CI finding", filtered)
	}
}

func TestModel_FilterMode_EscapeCancels(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	m.findings = []InspectFinding{
		{Finding: schema.Finding{ID: "F-CI-001", Title: "CI drift", Severity: schema.SeverityMedium}},
		{Finding: schema.Finding{ID: "F-ENV-001", Title: "Secret leak", Severity: schema.SeverityHigh}},
	}
	m.filtered = m.findings

	// Enter filter mode and type, then cancel
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	newM, _ = newM.(Model).Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'C'}})
	newM, _ = newM.(Model).Update(tea.KeyMsg{Type: tea.KeyEscape})

	if newM.(Model).filtering {
		t.Error("expected filtering=false after escape")
	}
	if len(newM.(Model).filtered) != 2 {
		t.Errorf("after escape: expected 2 findings, got %d", len(newM.(Model).filtered))
	}
}

func TestModel_ScanEventAndDone(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.sessionID = 1

	// Simulate scan started
	sess := &scanSession{id: 1, ch: make(chan app.Event, 2), done: make(chan struct{})}
	newM, _ := m.Update(scanStartedMsg{session: sess})
	m = newM.(Model)
	if !m.scanning {
		t.Error("expected scanning after scanStartedMsg")
	}

	// Simulate event
	newM, cmd := m.Update(scanEventMsg{sessionID: 1, event: app.Event{Type: app.EventCollectorStarted, Collector: "env"}})
	m = newM.(Model)
	if len(m.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(m.events))
	}
	if cmd == nil {
		t.Error("expected nextEvent cmd after scanEventMsg")
	}

	// Simulate done with report
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-TEST-001", Severity: schema.SeverityHigh, Confidence: 0.9, Title: "Test"},
		},
	}
	newM, _ = m.Update(scanDoneMsg{sessionID: 1, report: report})
	m = newM.(Model)
	if m.scanning {
		t.Error("expected scanning=false after scanDoneMsg")
	}
	if len(m.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(m.findings))
	}
}

type someError string

func (e someError) Error() string { return string(e) }

func TestModel_ScanDoneError(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.sessionID = 1
	m.session = &scanSession{id: 1}
	newM, _ := m.Update(scanDoneMsg{sessionID: 1, err: someError("bad")})
	m = newM.(Model)
	if m.scanErr == nil {
		t.Fatal("expected scanErr after failed scanDoneMsg")
	}
	if m.scanning {
		t.Error("expected scanning=false after failed scan")
	}
}

func TestModel_WindowSize(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	newM, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = newM.(Model)
	if m.width != 120 || m.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", m.width, m.height)
	}
}

func TestModel_QuitCancelsScan(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	// Start a scan session with a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	sess := &scanSession{
		ch:     make(chan app.Event, 256),
		done:   make(chan struct{}),
		cancel: cancel,
	}
	m.session = sess
	m.scanning = true

	// Simulate pressing q.
	newM, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	// Context should be cancelled.
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("expected scan context to be cancelled on quit")
	}
	_ = newM
}

func TestModel_RerunCancelsPreviousScan(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	sess := &scanSession{
		ch:     make(chan app.Event, 256),
		done:   make(chan struct{}),
		cancel: cancel,
	}
	m.session = sess
	m.scanning = true

	newM, cmd := m.ReRun()
	if !newM.scanning {
		t.Error("expected scanning=true after ReRun")
	}
	if cmd == nil {
		t.Error("expected non-nil cmd after ReRun")
	}
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("expected previous scan context to be cancelled on rerun")
	}
}

func TestModel_SmallTerminal_CompactView(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	m.findings = []InspectFinding{
		{Finding: schema.Finding{ID: "F-TEST-001", Severity: schema.SeverityHigh, Title: "Test finding"}},
	}
	m.filtered = m.findings

	// Very small terminal triggers compact view.
	newM, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 10})
	m = newM.(Model)
	v := m.View()
	if v == "" {
		t.Fatal("compact view should not be empty")
	}
	// Should contain the finding ID, not a two-panel layout.
	if !strings.Contains(v, "F-TEST-001") {
		t.Error("compact view should contain finding ID")
	}
}

func TestModel_LongEvidence_DoesNotPanic(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	longValue := strings.Repeat("a", 500)
	m.findings = []InspectFinding{
		{Finding: schema.Finding{
			ID:       "F-TEST-001",
			Severity: schema.SeverityHigh,
			Title:    "Test",
			Symptom:  strings.Repeat("x ", 200),
			Evidence: []schema.Evidence{
				{Source: "long", Value: longValue},
			},
			LikelyCauses: []string{strings.Repeat("cause ", 100)},
		}},
	}
	m.filtered = m.findings
	m.verbose = true
	m.width = 80
	m.height = 24

	// Should not panic.
	_ = m.View()
}

func TestModel_NoMutationKeybindings(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	m.scanning = false
	m.findings = []InspectFinding{{Finding: schema.Finding{ID: "X"}}}
	m.filtered = m.findings

	// List of keys that should NOT produce a mutation action.
	// We verify they don't crash and don't change findings/filtered.
	mutationKeys := []string{"a", "d", "f", "x", "1", "2", "3"}
	for _, k := range mutationKeys {
		newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		newModel := newM.(Model)
		if len(newModel.filtered) != len(m.filtered) {
			t.Errorf("key %q changed filtered count", k)
		}
	}
}

func TestModel_SafeEventSink_NoPanicAfterClose(t *testing.T) {
	sink := &safeEventSink{
		ch:   make(chan app.Event, 4),
		done: make(chan struct{}),
	}
	sink.Emit(app.Event{Type: app.EventScanStarted})
	sink.Close()
	// These should not panic.
	sink.Emit(app.Event{Type: app.EventScanStarted})
	sink.Emit(app.Event{Type: app.EventScanStarted})
}

func TestSafeEventSink_UnblocksOnCloseWhenChannelFull(t *testing.T) {
	sink := &safeEventSink{
		ch:   make(chan app.Event, 1),
		done: make(chan struct{}),
	}
	// Fill the channel
	sink.Emit(app.Event{Type: app.EventScanStarted})

	errCh := make(chan error, 1)
	go func() {
		// This should block initially, then unblock when Close() is called.
		sink.Emit(app.Event{Type: app.EventCollectorStarted})
		errCh <- nil
	}()

	sink.Close()

	select {
	case <-errCh:
		// success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Emit did not unblock after Close")
	}
}

func TestSafeEventSink_EmitAfterCloseDoesNotPanic(t *testing.T) {
	sink := &safeEventSink{
		ch:   make(chan app.Event, 1),
		done: make(chan struct{}),
	}
	sink.Close()
	sink.Emit(app.Event{Type: app.EventScanStarted}) // should return immediately
}

func TestSafeEventSink_CloseWhileEmitDoesNotPanic(t *testing.T) {
	for i := 0; i < 100; i++ {
		sink := &safeEventSink{
			ch:   make(chan app.Event, 1),
			done: make(chan struct{}),
		}
		go func() {
			sink.Emit(app.Event{Type: app.EventScanStarted})
			sink.Emit(app.Event{Type: app.EventScanStarted})
		}()
		go func() {
			sink.Close()
		}()
	}
}

func TestModel_ScanDone_WithEmptyFindings(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."}, nil)
	report := &schema.Report{
		Findings: []schema.Finding{},
	}
	newM, _ := m.Update(scanDoneMsg{report: report})
	m = newM.(Model)
	if m.scanning {
		t.Error("expected scanning=false")
	}
	if len(m.findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(m.findings))
	}
	// View should render empty state without panic.
	v := m.View()
	if v == "" {
		t.Error("empty findings view should not be empty")
	}
}
