package tui

import (
	"context"
	"sort"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/redact"
	"github.com/meedoomostafa/devdiag/internal/relevance"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// InspectFinding is an internal view model that enriches schema.Finding with
// derived fields for the TUI. It does not expand the public schema.
type InspectFinding struct {
	Finding           schema.Finding
	ConfidenceLabel   string
	Domain            string
	Target            string
	BlastRadius       string
	MutationRisk      string
	Reasoning         []string
	SuggestedCommands []CommandHint
	RelatedResources  []RelatedResource
}

// CommandHint represents a real devdiag command that helps investigate a finding.
type CommandHint struct {
	Title        string
	Command      string
	Kind         string
	MutationRisk string
}

// RelatedResource represents an external or internal resource linked to a finding.
type RelatedResource struct {
	Kind  string
	Value string
}

// severityRank returns a numeric rank for ordering findings.
func severityRank(s schema.Severity) int {
	switch s {
	case schema.SeverityCritical:
		return 4
	case schema.SeverityHigh:
		return 3
	case schema.SeverityMedium:
		return 2
	case schema.SeverityLow:
		return 1
	default:
		return 0
	}
}

// confidenceLabel derives a human-readable confidence level.
func confidenceLabel(c float64) string {
	if c >= 0.85 {
		return "high"
	}
	if c >= 0.60 {
		return "medium"
	}
	return "low"
}

// deriveInspectFinding builds an InspectFinding from a schema.Finding.
func deriveInspectFinding(f schema.Finding) InspectFinding {
	inf := InspectFinding{
		Finding:         f,
		ConfidenceLabel: confidenceLabel(f.Confidence),
		Domain:          deriveDomain(f),
		Target:          deriveTarget(f),
		BlastRadius:     deriveBlastRadius(f),
		MutationRisk:    deriveMutationRisk(f),
		Reasoning:       deriveReasoning(f),
	}
	inf.SuggestedCommands = deriveCommandHints(inf)
	inf.RelatedResources = deriveRelatedResources(inf)
	return inf
}

// BuildInspectFindings creates the internal view model list from a report.
func BuildInspectFindings(report *schema.Report) []InspectFinding {
	if report == nil {
		return nil
	}
	out := make([]InspectFinding, 0, len(report.Findings))
	for _, f := range report.Findings {
		out = append(out, deriveInspectFinding(f))
	}
	return out
}

// sortFindingsBySeverity orders findings from critical to info.
func sortFindingsBySeverity(findings []InspectFinding) []InspectFinding {
	// stable sort by severity rank descending, then confidence descending
	out := make([]InspectFinding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		ri := severityRank(out[i].Finding.Severity)
		rj := severityRank(out[j].Finding.Severity)
		if ri != rj {
			return ri > rj
		}
		return out[i].Finding.Confidence > out[j].Finding.Confidence
	})
	return out
}

// scanSession tracks a background scan and its results.
type scanSession struct {
	id     int
	ch     chan app.Event
	report *schema.Report
	err    error
	done   chan struct{}
	cancel context.CancelFunc
}

// Model is the Bubble Tea model for the inspect TUI.
type Model struct {
	// Configuration
	opts app.ScanOptions

	// Scan state
	scanning   bool
	events     []app.Event
	spinner    spinner.Model
	session    *scanSession
	sessionID  int
	scanErr    error
	report     *schema.Report
	fullReport *schema.Report

	// Redaction
	redactEngine *redact.Engine

	// Findings state
	findings      []InspectFinding
	filtered      []InspectFinding
	selected      int
	scrollOffset  int
	verbose       bool
	showHelp      bool
	filterInput   string
	filtering     bool
	includeHidden bool
	showHidden    bool
	hiddenCount   int

	// Dimensions (updated by WindowSizeMsg)
	width  int
	height int
}

// NewModel creates a TUI model for the given scan options and redaction engine.
func NewModel(opts app.ScanOptions, engine *redact.Engine, includeHidden ...bool) Model {
	showHidden := false
	if len(includeHidden) > 0 {
		showHidden = includeHidden[0]
	}
	return Model{
		opts:          opts,
		redactEngine:  engine,
		spinner:       newProgressSpinner(),
		includeHidden: showHidden,
		showHidden:    showHidden,
	}
}

// Report returns the final report from the TUI session.
func (m Model) Report() *schema.Report {
	return m.report
}

// StartScan initiates the background scan and returns the initial command.
func (m Model) StartScan() (Model, tea.Cmd) {
	if len(m.spinner.Spinner.Frames) == 0 {
		m.spinner = newProgressSpinner()
	}
	m.sessionID++
	m.scanning = true
	m.events = nil
	m.session = nil
	m.scanErr = nil
	m.report = nil
	m.fullReport = nil
	m.findings = nil
	m.filtered = nil
	m.selected = 0
	m.scrollOffset = 0

	return m, tea.Batch(startScan(m.opts, m.sessionID), m.spinner.Tick)
}

func (m Model) applyVisibility(report *schema.Report) Model {
	m.fullReport = report
	policy := relevance.PolicyFromReport(report, m.showHidden)
	filteredReport, summary := relevance.FilterReport(report, policy)
	m.report = filteredReport
	m.hiddenCount = summary.Hidden
	m.findings = sortFindingsBySeverity(BuildInspectFindings(filteredReport))
	m.filtered = ApplyFilters(m.findings, DefaultFilters())
	m.selected = 0
	m.scrollOffset = 0
	return m
}

// ReRun triggers a fresh scan, cancelling any active scan first.
func (m Model) ReRun() (Model, tea.Cmd) {
	m.cancelScan()
	return m.StartScan()
}
