package tui

import (
	"testing"

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
	m := NewModel(app.ScanOptions{Path: "/tmp"})
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
	m := NewModel(app.ScanOptions{Path: "."})
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

func TestModel_HelpToggle(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."})
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
	m := NewModel(app.ScanOptions{Path: "."})
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := m.Update(msg)
	if cmd == nil {
		t.Fatal("expected quit command")
	}
}

func TestModel_KeyToggleVerbose(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."})
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

func TestModel_FilterMode(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."})
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
	m := NewModel(app.ScanOptions{Path: "."})
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
	m := NewModel(app.ScanOptions{Path: "."})

	// Simulate scan started
	sess := &scanSession{ch: make(chan app.Event, 2), done: make(chan struct{})}
	newM, _ := m.Update(scanStartedMsg{session: sess})
	m = newM.(Model)
	if !m.scanning {
		t.Error("expected scanning after scanStartedMsg")
	}

	// Simulate event
	newM, cmd := m.Update(scanEventMsg{event: app.Event{Type: app.EventCollectorStarted, Collector: "env"}})
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
	newM, _ = m.Update(scanDoneMsg{report: report})
	m = newM.(Model)
	if m.scanning {
		t.Error("expected scanning=false after scanDoneMsg")
	}
	if len(m.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(m.findings))
	}
}

func TestModel_ScanDoneError(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."})
	newM, _ := m.Update(scanDoneMsg{err: &app.RulePackError{Errors: []string{"bad"}}})
	m = newM.(Model)
	if m.scanErr == nil {
		t.Fatal("expected scanErr after failed scanDoneMsg")
	}
	if m.scanning {
		t.Error("expected scanning=false after failed scan")
	}
}

func TestModel_WindowSize(t *testing.T) {
	m := NewModel(app.ScanOptions{Path: "."})
	newM, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = newM.(Model)
	if m.width != 120 || m.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", m.width, m.height)
	}
}
