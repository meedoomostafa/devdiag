package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	appTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	listStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#6C6C6C")).
			Padding(0, 1)

	detailStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#6C6C6C")).
			Padding(0, 1)

	selectedItemStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#7D56F4"))

	severityColors = map[schema.Severity]lipgloss.Color{
		schema.SeverityCritical: lipgloss.Color("#FF0000"),
		schema.SeverityHigh:     lipgloss.Color("#FF8C00"),
		schema.SeverityMedium:   lipgloss.Color("#FFD700"),
		schema.SeverityLow:      lipgloss.Color("#87CEEB"),
		schema.SeverityInfo:     lipgloss.Color("#808080"),
	}

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A0A0A0"))
)

func severityStyle(s schema.Severity) lipgloss.Style {
	c, ok := severityColors[s]
	if !ok {
		c = lipgloss.Color("#FAFAFA")
	}
	return lipgloss.NewStyle().Foreground(c).Bold(true)
}

// View satisfies tea.Model.
func (m Model) View() string {
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
	b.WriteString("  /            filter findings\n")
	b.WriteString("  ?            toggle this help\n")
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("Press ? or any key to close help."))
	return b.String()
}

func (m Model) renderProgress() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" DevDiag Inspect "))
	b.WriteString("\n\n")
	b.WriteString("Scanning...\n\n")

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

	names := make([]string, 0, len(collectorStatus))
	for name := range collectorStatus {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		evt := collectorStatus[name]
		switch evt.Type {
		case app.EventCollectorDone:
			statusStr := string(evt.Status)
			if statusStr == "" {
				statusStr = "done"
			}
			b.WriteString(fmt.Sprintf("  ● %-12s [%s]\n", name, statusStr))
		default:
			b.WriteString(fmt.Sprintf("  ○ %-12s [pending]\n", name))
		}
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

func (m Model) renderError() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" DevDiag Inspect "))
	b.WriteString("\n\n")
	b.WriteString("Scan failed.\n\n")
	b.WriteString(fmt.Sprintf("Error: %v\n", m.scanErr))
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("r:rerun  q:quit"))
	return b.String()
}

func (m Model) renderEmpty() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" DevDiag Inspect "))
	b.WriteString("\n\n")
	if len(m.findings) == 0 {
		b.WriteString("No findings.\n\n")
	} else {
		b.WriteString("No findings match the current filters.\n\n")
	}
	b.WriteString(helpStyle.Render("r:rerun  q:quit"))
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

	title := appTitleStyle.Render(" DevDiag Inspect ")

	listContent := m.renderList(listWidth)
	listPanel := listStyle.Width(listWidth).Height(m.height - 3).Render(listContent)

	detailContent := m.renderDetail(detailWidth)
	detailPanel := detailStyle.Width(detailWidth).Height(m.height - 3).Render(detailContent)

	footer := helpStyle.Render("q:quit r:rerun ↑k:prev ↓j:next v:verbose /:filter ?:help")

	body := lipgloss.JoinHorizontal(lipgloss.Top, listPanel, detailPanel)
	return lipgloss.JoinVertical(lipgloss.Left, title, body, footer)
}

// renderCompact shows a single-column stacked layout for small terminals.
func (m Model) renderCompact() string {
	var b strings.Builder
	b.WriteString(appTitleStyle.Render(" DevDiag Inspect "))
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

	b.WriteString(helpStyle.Render("q:quit r:rerun ↑k:prev ↓j:next ?:help"))
	return b.String()
}

func (m Model) renderList(width int) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Findings (%d)\n\n", len(m.filtered)))

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
