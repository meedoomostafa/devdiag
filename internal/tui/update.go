package tui

import (
	"context"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/domain"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// scanStartedMsg signals that a background scan has begun.
type scanStartedMsg struct {
	session *scanSession
}

// scanEventMsg carries a single event from the scan.
type scanEventMsg struct {
	sessionID int
	event     app.Event
}

// scanDoneMsg signals scan completion with the final report.
type scanDoneMsg struct {
	sessionID int
	report    *schema.Report
	err       error
}

// safeEventSink ensures progress events never deadlock or panic, even
// if the TUI exits or the scan is cancelled. Progress events are
// best-effort after cancellation.
type safeEventSink struct {
	ch   chan app.Event
	done chan struct{}
	once sync.Once
}

func (s *safeEventSink) Emit(e app.Event) {
	select {
	case <-s.done:
		return
	default:
	}

	select {
	case s.ch <- e:
	case <-s.done:
		return
	}
}

func (s *safeEventSink) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}

// startScan begins app.Scan in a background goroutine and returns the
// session handle as a tea.Msg.
func startScan(opts app.ScanOptions, sessionID int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		sink := &safeEventSink{
			ch:   make(chan app.Event, 256),
			done: make(chan struct{}),
		}
		sess := &scanSession{
			id:     sessionID,
			ch:     sink.ch,
			done:   make(chan struct{}),
			cancel: cancel,
		}
		go func() {
			sess.report, sess.err = app.Scan(ctx, opts, sink)
			sink.Close()
			close(sess.done)
		}()
		return scanStartedMsg{session: sess}
	}
}

// nextEvent reads the next event from the scan session channel.
func nextEvent(sess *scanSession) tea.Cmd {
	return func() tea.Msg {
		select {
		case evt, ok := <-sess.ch:
			if !ok {
				// sess.ch should not be closed while producers are active.
				// If we hit this, it means something closed the channel unexpectedly.
				<-sess.done
				return scanDoneMsg{sessionID: sess.id, report: sess.report, err: sess.err}
			}
			return scanEventMsg{sessionID: sess.id, event: evt}
		case <-sess.done:
			// Scan goroutine finished or cancelled.
			// Drain remaining events if any, otherwise return completion.
			select {
			case evt := <-sess.ch:
				return scanEventMsg{sessionID: sess.id, event: evt}
			default:
				return scanDoneMsg{sessionID: sess.id, report: sess.report, err: sess.err}
			}
		}
	}
}

// Init satisfies tea.Model.
func (m Model) Init() tea.Cmd {
	if m.mode != ModeScan {
		return nil
	}
	if len(m.spinner.Spinner.Frames) == 0 {
		m.spinner = newProgressSpinner()
	}
	return tea.Batch(
		startScan(m.opts, m.sessionID),
		m.spinner.Tick,
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
		if m.session == nil || msg.sessionID != m.session.id {
			return m, nil
		}
		m.events = append(m.events, msg.event)
		return m, nextEvent(m.session)

	case scanDoneMsg:
		if m.session == nil || msg.sessionID != m.session.id {
			return m, nil
		}
		m.scanning = false
		m.report = msg.report
		m.scanErr = msg.err
		if msg.report != nil {
			report := msg.report
			if m.redactEngine != nil {
				report = m.redactEngine.RedactReport(msg.report)
			}
			m = m.applyVisibility(report)
		}
		return m, nil

	case spinner.TickMsg:
		if !m.scanning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

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
		m.statusBarMsg = ""
		return m.ReRun()
	case "v":
		m.verbose = !m.verbose
		return m, nil
	case "h":
		if m.fullReport != nil {
			m.showHidden = !m.showHidden
			m = m.applyVisibility(m.fullReport)
		}
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
	case "0":
		m.activeFilters.Domain = ""
		m.statusBarMsg = "Domain filter cleared"
		m = m.applyActiveFilters()
		return m, nil
	default:
		if dom, ok := domain.FindDomainByTUIKey(msg.String()); ok {
			m.activeFilters.Domain = dom.Name
			m.statusBarMsg = "Filter: " + dom.Name
			m = m.applyActiveFilters()
			return m, nil
		}
	}

	return m, nil
}

func (m Model) handleFilterKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filtering = false
		m.activeFilters.Text = strings.TrimSpace(m.filterInput)
		m = m.applyActiveFilters()
		return m, nil
	case tea.KeyEscape:
		m.filtering = false
		m.filterInput = ""
		m.activeFilters.Text = ""
		m = m.applyActiveFilters()
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
