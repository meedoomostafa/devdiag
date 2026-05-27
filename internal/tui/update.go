package tui

import (
	"context"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// scanStartedMsg signals that a background scan has begun.
type scanStartedMsg struct {
	session *scanSession
}

// scanEventMsg carries a single event from the scan.
type scanEventMsg struct {
	event app.Event
}

// scanDoneMsg signals scan completion with the final report.
type scanDoneMsg struct {
	report *schema.Report
	err    error
}

// safeEventSink wraps a channel with a mutex so Emit never panics
// when the channel is closed (e.g. after scan cancellation).
type safeEventSink struct {
	mu     sync.Mutex
	ch     chan app.Event
	closed bool
}

func (s *safeEventSink) Emit(e app.Event) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.ch <- e
}

func (s *safeEventSink) close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	s.mu.Unlock()
}

// startScan begins app.Scan in a background goroutine and returns the
// session handle as a tea.Msg.
func startScan(opts app.ScanOptions) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		sink := &safeEventSink{ch: make(chan app.Event, 256)}
		sess := &scanSession{
			ch:     sink.ch,
			done:   make(chan struct{}),
			cancel: cancel,
		}
		go func() {
			sess.report, sess.err = app.Scan(ctx, opts, sink)
			sink.close()
			close(sess.done)
		}()
		return scanStartedMsg{session: sess}
	}
}

// nextEvent reads the next event from the scan session channel.
func nextEvent(sess *scanSession) tea.Cmd {
	return func() tea.Msg {
		evt, ok := <-sess.ch
		if !ok {
			// Channel closed; wait for goroutine to set report/err.
			<-sess.done
			return scanDoneMsg{report: sess.report, err: sess.err}
		}
		return scanEventMsg{event: evt}
	}
}

// Init satisfies tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		startScan(m.opts),
	)
}

// Update satisfies tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case scanStartedMsg:
		m.scanning = true
		m.session = msg.session
		m.events = nil
		return m, nextEvent(msg.session)

	case scanEventMsg:
		m.events = append(m.events, msg.event)
		return m, nextEvent(m.session)

	case scanDoneMsg:
		m.scanning = false
		m.report = msg.report
		m.scanErr = msg.err
		if msg.report != nil {
			report := msg.report
			if m.redactEngine != nil {
				report = m.redactEngine.RedactReport(msg.report)
			}
			m.findings = sortFindingsBySeverity(BuildInspectFindings(report))
			m.filtered = ApplyFilters(m.findings, DefaultFilters())
			m.selected = 0
			m.scrollOffset = 0
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	// Global keys that work in any mode
	switch msg.String() {
	case "q", "ctrl+c":
		m.cancelScan()
		return m, tea.Quit
	case "?":
		m.showHelp = !m.showHelp
		return m, nil
	}

	if m.filtering {
		return m.handleFilterKey(msg)
	}

	// Normal mode keys
	switch msg.String() {
	case "r":
		return m.ReRun()
	case "v":
		m.verbose = !m.verbose
		return m, nil
	case "/":
		m.filtering = true
		m.filterInput = ""
		return m, nil
	case "up", "k":
		m.prevFinding()
		return m, nil
	case "down", "j":
		m.nextFinding()
		return m, nil
	}

	return m, nil
}

func (m Model) handleFilterKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filtering = false
		af := DefaultFilters()
		af.Text = strings.TrimSpace(m.filterInput)
		m.filtered = ApplyFilters(m.findings, af)
		m.selected = 0
		m.scrollOffset = 0
		return m, nil
	case tea.KeyEscape:
		m.filtering = false
		m.filterInput = ""
		m.filtered = ApplyFilters(m.findings, DefaultFilters())
		m.selected = 0
		m.scrollOffset = 0
		return m, nil
	case tea.KeyBackspace:
		if len(m.filterInput) > 0 {
			m.filterInput = m.filterInput[:len(m.filterInput)-1]
		}
		return m, nil
	case tea.KeyRunes:
		m.filterInput += string(msg.Runes)
		return m, nil
	}
	return m, nil
}

func (m *Model) maxVisibleItems() int {
	maxItems := (m.height - 7) / 2
	if maxItems < 1 {
		maxItems = 1
	}
	return maxItems
}

func (m *Model) adjustScroll() {
	maxItems := m.maxVisibleItems()
	if m.selected < m.scrollOffset {
		m.scrollOffset = m.selected
	}
	if m.selected >= m.scrollOffset+maxItems {
		m.scrollOffset = m.selected - maxItems + 1
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
	if m.scrollOffset > len(m.filtered)-maxItems {
		if len(m.filtered) > maxItems {
			m.scrollOffset = len(m.filtered) - maxItems
		} else {
			m.scrollOffset = 0
		}
	}
}

func (m *Model) nextFinding() {
	if len(m.filtered) == 0 {
		return
	}
	if m.selected < len(m.filtered)-1 {
		m.selected++
		m.adjustScroll()
	}
}

func (m *Model) prevFinding() {
	if m.selected > 0 {
		m.selected--
		m.adjustScroll()
	}
}

// cancelScan cancels the active scan goroutine if one exists.
func (m *Model) cancelScan() {
	if m.session != nil && m.session.cancel != nil {
		m.session.cancel()
	}
}
