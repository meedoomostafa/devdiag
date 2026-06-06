package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/domain"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	appTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F4F4F5")).
			Background(lipgloss.Color("#27272A")).
			Padding(0, 1)

	listStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#3F3F46")).
			Padding(0, 1)

	detailStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#3F3F46")).
			Padding(0, 1)

	selectedItemStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#3F3F46"))

	accentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#A7F3D0"))

	severityColors = map[schema.Severity]lipgloss.Color{
		schema.SeverityCritical: lipgloss.Color("#F87171"),
		schema.SeverityHigh:     lipgloss.Color("#FB923C"),
		schema.SeverityMedium:   lipgloss.Color("#FACC15"),
		schema.SeverityLow:      lipgloss.Color("#38BDF8"),
		schema.SeverityInfo:     lipgloss.Color("#A1A1AA"),
	}

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A1A1AA"))

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#71717A"))
)

func newProgressSpinner() spinner.Model {
	return spinner.New(
		spinner.WithSpinner(spinner.Line),
		spinner.WithStyle(accentStyle),
	)
}

func severityStyle(s schema.Severity) lipgloss.Style {
	c, ok := severityColors[s]
	if !ok {
		c = lipgloss.Color("#FAFAFA")
	}
	return lipgloss.NewStyle().Foreground(c).Bold(true)
}

// View satisfies tea.Model.
func (m Model) View() string {
	if m.width < 40 || m.height < 8 {
		return "Terminal too small"
	}
	if m.showHelp {
		return m.renderHelp()
	}
	if m.scanning {
		return m.renderProgress()
	}
	if m.scanErr != nil {
		return m.renderError()
	}
	if len(m.filtered) == 0 {
		return m.renderEmpty()
	}
	return m.renderFindings()
}

func (m Model) renderHelp() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" DevDiag Inspect — Help "))
	b.WriteString("\n\n")
	b.WriteString("Navigation\n")
	b.WriteString("  q / ctrl+c   quit\n")
	b.WriteString("  r            rerun scan\n")
	b.WriteString("  up / k       previous finding\n")
	b.WriteString("  down / j     next finding\n")
	b.WriteString("  v            toggle verbose evidence\n")
	b.WriteString("  e            open evidence panel\n")
	b.WriteString("  tab          switch detail/evidence panel\n")
	b.WriteString("  pgup/pgdn    previous/next evidence page\n")
	b.WriteString("  c            show command to copy\n")
	b.WriteString("  x            run safe read-only command (disabled)\n")
	b.WriteString("  f            show fix dry-run command\n")
	b.WriteString("  h            toggle hidden low/info findings\n")
	b.WriteString("  /            filter findings\n")
	b.WriteString("  ?            toggle this help\n")
	b.WriteString("\n")
	b.WriteString("Domain Filters\n")
	b.WriteString("  0            clear domain filter\n")
	for _, dom := range domain.GetTUIMappedDomains() {
		b.WriteString(fmt.Sprintf("  %s            %s\n", dom.TUIKey, dom.Name))
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("Press ? or any key to close help."))
	return b.String()
}

func (m Model) renderProgress() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" " + m.inspectTitle() + " "))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("%s scanning %s\n", m.spinner.View(), mutedStyle.Render(m.scanDisplayPath())))

	collectorStatus := make(map[string]app.Event)
	for _, e := range m.events {
		if e.Type == app.EventCollectorDone && e.Collector != "" {
			collectorStatus[e.Collector] = e
		}
	}
	for _, e := range m.events {
		if e.Type == app.EventCollectorStarted && e.Collector != "" {
			if _, ok := collectorStatus[e.Collector]; !ok {
				collectorStatus[e.Collector] = app.Event{Type: app.EventCollectorStarted, Collector: e.Collector}
			}
		}
	}

	var doneCount, activeCount, partialCount int
	names := make([]string, 0, len(collectorStatus))
	for name := range collectorStatus {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		evt := collectorStatus[name]
		if evt.Type == app.EventCollectorDone {
			doneCount++
			if evt.Status == schema.CollectorPartial || evt.Status == schema.CollectorTimeout || evt.Status == schema.CollectorPermissionDenied || evt.Status == schema.CollectorUnavailable || evt.Status == schema.CollectorFailed {
				partialCount++
			}
			continue
		}
		activeCount++
	}
	b.WriteString(fmt.Sprintf("Collectors: %d done, %d running, %d need review\n\n", doneCount, activeCount, partialCount))

	for _, name := range names {
		evt := collectorStatus[name]
		b.WriteString(fmt.Sprintf("  %-8s %s\n", collectorStatusLabel(evt), name))
	}

	if len(m.events) > 0 {
		last := m.events[len(m.events)-1]
		if last.Message != "" {
			b.WriteString("\n")
			b.WriteString(helpStyle.Render(fmt.Sprintf("Latest: %s", last.Message)))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("q:quit"))
	return b.String()
}

func collectorStatusLabel(evt app.Event) string {
	if evt.Type != app.EventCollectorDone {
		return mutedStyle.Render("[run]")
	}
	switch evt.Status {
	case "", schema.CollectorOK:
		return accentStyle.Render("[ok]")
	case schema.CollectorPartial:
		return severityStyle(schema.SeverityMedium).Render("[partial]")
	case schema.CollectorTimeout:
		return severityStyle(schema.SeverityMedium).Render("[timeout]")
	case schema.CollectorPermissionDenied:
		return severityStyle(schema.SeverityHigh).Render("[denied]")
	case schema.CollectorUnavailable:
		return mutedStyle.Render("[unavail]")
	case schema.CollectorFailed:
		return severityStyle(schema.SeverityHigh).Render("[failed]")
	default:
		return mutedStyle.Render("[" + string(evt.Status) + "]")
	}
}

func (m Model) scanDisplayPath() string {
	path := strings.TrimSpace(m.opts.Path)
	if path == "" {
		return "."
	}
	return path
}

func (m Model) renderError() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" " + m.inspectTitle() + " "))
	b.WriteString("\n\n")
	b.WriteString("Scan failed.\n\n")
	b.WriteString(fmt.Sprintf("Error: %v\n", m.scanErr))
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("r:rerun  q:quit"))
	return b.String()
}

func (m Model) renderEmpty() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" " + m.inspectTitle() + " "))
	b.WriteString("\n\n")
	if len(m.findings) == 0 {
		if m.hiddenCount > 0 {
			b.WriteString("No actionable findings at the default visibility level.\n\n")
			b.WriteString(fmt.Sprintf("%d hidden low/info finding(s) are available with h.\n\n", m.hiddenCount))
		} else {
			b.WriteString("No findings.\n\n")
		}
	} else {
		b.WriteString("No findings match the current filters.\n\n")
	}
	footerText := "h:hidden r:rerun q:quit"
	if m.statusBarMsg != "" {
		footerText = fmt.Sprintf("%s | %s", footerText, m.statusBarMsg)
	}
	b.WriteString(helpStyle.Render(footerText))
	return b.String()
}

func (m Model) renderFindings() string {
	if m.width == 0 {
		m.width = 80
	}
	if m.height == 0 {
		m.height = 24
	}

	// Fallback for very small terminals: render a compact single-column view.
	if m.width < 60 || m.height < 12 {
		return m.renderCompact()
	}

	listWidth := m.width / 3
	if listWidth < 25 {
		listWidth = 25
	}
	detailWidth := m.width - listWidth - 4
	if detailWidth < 30 {
		detailWidth = 30
	}

	title := appTitleStyle.Render(" " + m.inspectTitle() + " ")
	header := helpStyle.Render(m.renderModeSummary())

	listContent := m.renderList(listWidth)
	listPanel := listStyle.Width(listWidth).Height(m.height - 4).Render(listContent)

	detailContent := m.renderDetail(detailWidth)
	if m.activePane == paneEvidence {
		detailContent = m.renderEvidencePanel(detailWidth)
	}
	detailPanel := detailStyle.Width(detailWidth).Height(m.height - 4).Render(detailContent)

	footerText := "q:quit r:rerun ↑k:prev ↓j:next h:hidden v:verbose e:evidence tab:pane c:copy f:fix 0-6:domain ?:help"
	if m.statusBarMsg != "" {
		footerText = fmt.Sprintf("%s | %s", footerText, m.statusBarMsg)
	}
	footer := helpStyle.Render(footerText)

	body := lipgloss.JoinHorizontal(lipgloss.Top, listPanel, detailPanel)
	return lipgloss.JoinVertical(lipgloss.Left, title, header, body, footer)
}

// renderCompact shows a single-column stacked layout for small terminals.
func (m Model) renderCompact() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" " + m.inspectTitle() + " "))
	b.WriteString("\n\n")

	if m.selected < len(m.filtered) {
		f := m.filtered[m.selected]
		b.WriteString(fmt.Sprintf("%d/%d ", m.selected+1, len(m.filtered)))
		b.WriteString(severityStyle(f.Finding.Severity).Render(string(f.Finding.Severity)))
		b.WriteString(" ")
		b.WriteString(lipgloss.NewStyle().Bold(true).Render(f.Finding.ID))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render(f.Finding.Title))
		b.WriteString("\n\n")
		b.WriteString(fmt.Sprintf("Confidence: %s (%.2f)  Domain: %s  Blast: %s  Mut: %s\n",
			f.ConfidenceLabel, f.Finding.Confidence, f.Domain, f.BlastRadius, f.MutationRisk))
		if f.Finding.Symptom != "" {
			b.WriteString(wrapText(f.Finding.Symptom, m.width-2))
			b.WriteString("\n\n")
		}
	} else {
		b.WriteString("No findings.\n\n")
	}

	footerText := "q:quit r:rerun ↑k:prev ↓j:next h:hidden e:evidence 0-6:domain ?:help"
	if m.statusBarMsg != "" {
		footerText = fmt.Sprintf("%s | %s", footerText, m.statusBarMsg)
	}
	b.WriteString(helpStyle.Render(footerText))
	return b.String()
}

func (m Model) renderList(width int) string {
	var b strings.Builder
	title := "Actionable findings"
	if m.showHidden {
		title = "All findings"
	}
	b.WriteString(fmt.Sprintf("%s (%d)\n", title, len(m.filtered)))
	if !m.showHidden && m.hiddenCount > 0 {
		b.WriteString(helpStyle.Render(fmt.Sprintf("%d hidden, press h", m.hiddenCount)))
	}
	b.WriteString("\n\n")

	maxItems := m.maxVisibleItems()
	if maxItems < 1 {
		maxItems = 1
	}
	start := m.scrollOffset
	if start < 0 {
		start = 0
	}
	end := start + maxItems
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	for i := start; i < end; i++ {
		f := m.filtered[i]
		label := fmt.Sprintf("[%s]", f.Finding.Severity)
		line := fmt.Sprintf("%-12s %s", label, f.Finding.ID)
		if i == m.selected {
			line = selectedItemStyle.Width(width - 2).Render(line)
		} else {
			line = severityStyle(f.Finding.Severity).Render(label) + " " + lipgloss.NewStyle().Render(f.Finding.ID)
		}
		b.WriteString(line)
		b.WriteString("\n")
		if len(f.Finding.Title) > 0 {
			title := f.Finding.Title
			if len(title) > width-4 {
				title = title[:width-7] + "..."
			}
			if i == m.selected {
				b.WriteString(selectedItemStyle.Width(width - 2).Render("  " + title))
				b.WriteString("\n")
			} else {
				b.WriteString("  " + helpStyle.Render(title))
				b.WriteString("\n")
			}
		}
	}
	if m.filtering {
		b.WriteString("\n")
		b.WriteString(helpStyle.Render(fmt.Sprintf("Filter: %s_", m.filterInput)))
	}
	return b.String()
}

func (m Model) renderDetail(width int) string {
	if m.selected >= len(m.filtered) {
		return ""
	}
	f := m.filtered[m.selected]
	var b strings.Builder

	b.WriteString(severityStyle(f.Finding.Severity).Render(string(f.Finding.Severity)))
	b.WriteString(" ")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(f.Finding.Title))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("ID:          %s\n", f.Finding.ID))
	b.WriteString(fmt.Sprintf("Confidence:  %s (%.2f)\n", f.ConfidenceLabel, f.Finding.Confidence))
	b.WriteString(fmt.Sprintf("Domain:      %s\n", f.Domain))
	b.WriteString(fmt.Sprintf("Target:      %s\n", f.Target))
	b.WriteString(fmt.Sprintf("Blast:       %s\n", f.BlastRadius))
	b.WriteString(fmt.Sprintf("Mut. risk:   %s\n", f.MutationRisk))
	b.WriteString("\n")

	if f.Finding.Symptom != "" {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Symptom"))
		b.WriteString("\n")
		b.WriteString(wrapText(f.Finding.Symptom, width-2))
		b.WriteString("\n\n")
	}

	if m.verbose && len(f.Finding.Evidence) > 0 {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Evidence"))
		b.WriteString("\n")
		for _, ev := range f.Finding.Evidence {
			val := ev.Value
			if len(val) > width-6 {
				val = val[:width-9] + "..."
			}
			b.WriteString(fmt.Sprintf("  %s = %s\n", ev.Source, val))
		}
		b.WriteString("\n")
	}

	if len(f.Reasoning) > 0 {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Why DevDiag thinks this"))
		b.WriteString("\n")
		for _, r := range f.Reasoning {
			b.WriteString(wrapText("- "+r, width-2))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(f.Finding.LikelyCauses) > 0 {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Likely causes"))
		b.WriteString("\n")
		for _, c := range f.Finding.LikelyCauses {
			b.WriteString(wrapText("- "+c, width-2))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(f.SuggestedCommands) > 0 {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Suggested commands"))
		b.WriteString("\n")
		for _, cmd := range f.SuggestedCommands {
			risk := ""
			if cmd.MutationRisk != "" && cmd.MutationRisk != "none" {
				risk = fmt.Sprintf(" (mut. risk: %s)", cmd.MutationRisk)
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cmd.Command, risk))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderEvidencePanel(width int) string {
	f, ok := m.selectedFinding()
	if !ok {
		return ""
	}
	var b strings.Builder
	pageCount := m.evidencePageCount()
	if m.evidencePage >= pageCount {
		m.evidencePage = pageCount - 1
	}
	if m.evidencePage < 0 {
		m.evidencePage = 0
	}
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Evidence"))
	b.WriteString(fmt.Sprintf("  Page %d/%d\n\n", m.evidencePage+1, pageCount))
	if len(f.Finding.Evidence) == 0 {
		b.WriteString("No evidence attached to this finding.\n")
		return b.String()
	}
	size := evidencePageSize()
	start := m.evidencePage * size
	end := start + size
	if end > len(f.Finding.Evidence) {
		end = len(f.Finding.Evidence)
	}
	for _, ev := range f.Finding.Evidence[start:end] {
		val := ev.Value
		if len(val) > width-6 {
			val = val[:width-9] + "..."
		}
		b.WriteString(fmt.Sprintf("%s\n", lipgloss.NewStyle().Bold(true).Render(ev.Source)))
		b.WriteString(wrapText(val, width-2))
		b.WriteString("\n\n")
	}
	return b.String()
}

func wrapText(text string, width int) string {
	if width <= 0 {
		width = 40
	}
	var result strings.Builder
	lineLen := 0
	for _, word := range strings.Fields(text) {
		wlen := len(word)
		if lineLen > 0 && lineLen+1+wlen > width {
			result.WriteString("\n")
			lineLen = 0
		}
		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += wlen
	}
	return result.String()
}

func (m Model) inspectTitle() string {
	switch m.mode {
	case ModeScan:
		return "DevDiag Inspect — scan"
	case ModeReport:
		return fmt.Sprintf("DevDiag Inspect — report (%s)", m.sourceName)
	case ModeRun:
		return fmt.Sprintf("DevDiag Inspect — run %s", m.sourceName)
	default:
		return "DevDiag Inspect"
	}
}

func (m Model) modeLabel() string {
	switch m.mode {
	case ModeScan:
		return "scan"
	case ModeReport:
		return "saved report"
	case ModeRun:
		if m.sourceName != "" {
			return "run " + m.sourceName
		}
		return "run"
	default:
		return "unknown"
	}
}

func (m Model) renderModeSummary() string {
	collectorSummary := m.collectorStatusSummary()
	return fmt.Sprintf("Mode: %s | Findings: %d actionable, %d hidden | Collectors: %s",
		m.modeLabel(), len(m.findings), m.hiddenCount, collectorSummary)
}

func (m Model) collectorStatusSummary() string {
	if m.report == nil || len(m.report.Collectors) == 0 {
		return "0"
	}
	counts := map[schema.CollectorStatus]int{}
	for _, collector := range m.report.Collectors {
		status := collector.Status
		if status == "" {
			status = schema.CollectorOK
		}
		counts[status]++
	}
	order := []schema.CollectorStatus{
		schema.CollectorOK,
		schema.CollectorPartial,
		schema.CollectorTimeout,
		schema.CollectorUnavailable,
		schema.CollectorPermissionDenied,
		schema.CollectorFailed,
	}
	labels := map[schema.CollectorStatus]string{
		schema.CollectorOK:               "ok",
		schema.CollectorPartial:          "partial",
		schema.CollectorTimeout:          "timeout",
		schema.CollectorUnavailable:      "unavailable",
		schema.CollectorPermissionDenied: "permission denied",
		schema.CollectorFailed:           "failed",
	}
	var parts []string
	for _, status := range order {
		if counts[status] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[status], labels[status]))
		}
	}
	if len(parts) == 0 {
		return "0"
	}
	return strings.Join(parts, ", ")
}
