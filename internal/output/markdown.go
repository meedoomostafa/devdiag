package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// MarkdownRenderer emits a structured Markdown report.
type MarkdownRenderer struct {
	HiddenCount int
}

func (r *MarkdownRenderer) Render(report *schema.Report, w io.Writer) error {
	var b strings.Builder
	b.WriteString("# DevDiag Report\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("|---|---|\n")
	b.WriteString(fmt.Sprintf("| Version | %s |\n", report.DevDiagVersion))
	b.WriteString(fmt.Sprintf("| Repo | %s |\n", report.Repo.Root))
	b.WriteString(fmt.Sprintf("| Findings | %d actionable, %d hidden |\n", len(report.Findings), r.HiddenCount))
	b.WriteString(fmt.Sprintf("| Highest severity | %s |\n\n", mdHighestSeverity(report.Findings)))

	if r.HiddenCount > 0 {
		b.WriteString(fmt.Sprintf("%d hidden finding(s) are not shown at this visibility level. Re-run with `--include-hidden` or an audit view to show them when policy allows.\n\n", r.HiddenCount))
	}

	renderMarkdownCollectorSummary(report, &b)
	if info, ok := findTraceUnavailable(report); ok {
		renderTraceUnavailableMarkdown(info, &b)
	}

	if len(report.Findings) > 0 {
		b.WriteString("## Actionable findings\n\n")
		b.WriteString("| Severity | ID | Summary | Confidence |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, f := range report.Findings {
			title := mdSummarizeFindingTitle(f)
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %.2f |\n", f.Severity, f.ID, title, f.Confidence))
		}
		b.WriteString("\n")

		b.WriteString("## Details\n\n")
		for _, f := range report.Findings {
			title := mdSummarizeFindingTitle(f)
			b.WriteString(fmt.Sprintf("<details>\n<summary>%s — %s</summary>\n\n", f.ID, title))
			if f.Symptom != "" {
				b.WriteString(fmt.Sprintf("**Symptom:** %s\n\n", f.Symptom))
			}
			if len(f.Evidence) > 0 {
				b.WriteString("**Evidence:**\n\n")
				renderMarkdownEvidence(f.Evidence, &b)
				b.WriteString("\n")
			}
			if len(f.LikelyCauses) > 0 {
				b.WriteString("**Likely causes:**\n\n")
				for _, cause := range f.LikelyCauses {
					b.WriteString(fmt.Sprintf("- %s\n", cause))
				}
				b.WriteString("\n")
			}
			if len(f.FixHints) > 0 {
				b.WriteString("**Fix hints:**\n\n")
				for _, hint := range f.FixHints {
					b.WriteString(fmt.Sprintf("- %s\n", hint))
				}
				b.WriteString("\n")
			}
			b.WriteString("</details>\n\n")
		}
	} else if r.HiddenCount > 0 {
		b.WriteString("No actionable findings at the default visibility level.\n\n")
	} else {
		b.WriteString("No findings.\n\n")
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

func renderMarkdownCollectorSummary(report *schema.Report, b *strings.Builder) {
	if report == nil || len(report.Collectors) == 0 {
		return
	}
	summary := summarizeCollectors(report)
	b.WriteString("## Collector Summary\n\n")
	b.WriteString("| Collector | Status | Evidence | Notes |\n")
	b.WriteString("|---|---|---:|---:|\n")
	for _, collector := range report.Collectors {
		status := string(collector.Status)
		if status == "" {
			status = string(schema.CollectorOK)
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d |\n", collector.Name, status, len(collector.Evidence), len(collector.Notes)))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Totals: %d ok, %d partial, %d timeout, %d unavailable, %d permission denied, %d failed.\n\n",
		summary.OK, summary.Partial, summary.Timeout, summary.Unavailable, summary.PermissionDenied, summary.Failed))
	if hasUnavailableCollectors(report.Collectors) {
		b.WriteString("**Collector notes:**\n\n")
		for _, collector := range report.Collectors {
			if collector.Status == schema.CollectorOK || collector.Status == "" {
				continue
			}
			if len(collector.Notes) == 0 {
				b.WriteString(fmt.Sprintf("- `%s`: %s\n", collector.Name, collector.Status))
				continue
			}
			for _, note := range collector.Notes {
				b.WriteString(fmt.Sprintf("- `%s`: %s\n", collector.Name, note))
			}
		}
		b.WriteString("\n")
	}
}

func renderTraceUnavailableMarkdown(info traceUnavailableInfo, b *strings.Builder) {
	b.WriteString("## Trace Unavailable\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("|---|---|\n")
	if info.Backend != "" {
		b.WriteString(fmt.Sprintf("| Backend | %s |\n", info.Backend))
	}
	if info.Reason != "" {
		b.WriteString(fmt.Sprintf("| Reason | %s |\n", info.Reason))
	}
	if info.Command != "" {
		b.WriteString(fmt.Sprintf("| Command | `%s` |\n", info.Command))
	}
	b.WriteString("\n")
	b.WriteString("Next:\n\n")
	b.WriteString("- Install strace\n")
	b.WriteString("- Or use `--backend ebpf` when available\n\n")
}

func renderMarkdownEvidence(evidence []schema.Evidence, b *strings.Builder) {
	if keys, ok := evidenceKeys(evidence, "missing_keys", "missing_optional_keys"); ok {
		for _, key := range keys {
			b.WriteString(fmt.Sprintf("- %s\n", key))
		}
		return
	}

	maxEv := 5
	for idx, ev := range evidence {
		if idx >= maxEv {
			b.WriteString(fmt.Sprintf("- and %d more\n", len(evidence)-maxEv))
			break
		}
		val := ev.Value
		if len(val) > 200 {
			val = val[:197] + "..."
		}
		if strings.HasPrefix(ev.Source, "ci_run__") {
			b.WriteString(fmt.Sprintf("- `%s`:\n\n```sh\n%s\n```\n", ev.Source, val))
			continue
		}
		b.WriteString(fmt.Sprintf("- `%s`: %s\n", ev.Source, val))
	}
}

func evidenceKeys(evidence []schema.Evidence, sources ...string) ([]string, bool) {
	sourceSet := make(map[string]bool, len(sources))
	for _, source := range sources {
		sourceSet[source] = true
	}
	var keys []string
	for _, ev := range evidence {
		if !sourceSet[ev.Source] {
			continue
		}
		for _, part := range strings.Split(ev.Value, ",") {
			key := strings.TrimSpace(part)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys, len(keys) > 0
}

func mdHighestSeverity(findings []schema.Finding) schema.Severity {
	highest := schema.SeverityInfo
	rank := func(s schema.Severity) int {
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
	for _, f := range findings {
		if rank(f.Severity) > rank(highest) {
			highest = f.Severity
		}
	}
	return highest
}

func mdSummarizeFindingTitle(f schema.Finding) string {
	switch f.ID {
	case "F-ENV-001", "F-ENV-001-OPTIONAL":
		count := 0
		for _, ev := range f.Evidence {
			if ev.Source == "missing_keys" || ev.Source == "missing_optional_keys" {
				if parts := strings.Split(ev.Value, ", "); len(parts) > 0 && ev.Value != "" {
					count += len(parts)
				}
			}
		}
		if count > 0 {
			if strings.Contains(strings.ToLower(f.Title), "optional") || f.ID == "F-ENV-001-OPTIONAL" {
				return fmt.Sprintf("%d optional env keys missing from .env", count)
			}
			return fmt.Sprintf("%d env keys missing from .env", count)
		}
		return f.Title
	case "F-CI-ENV-001":
		count := 0
		for _, ev := range f.Evidence {
			if ev.Source == "ci_env" {
				count++
			}
		}
		if count > 0 {
			return fmt.Sprintf("%d CI env vars not found locally", count)
		}
		return f.Title
	case "F-CI-ENV-DEPLOY-INFO":
		count := 0
		for _, ev := range f.Evidence {
			if ev.Source == "ci_env" {
				count++
			}
		}
		if count > 0 {
			return fmt.Sprintf("%d CI deployment env vars not found locally", count)
		}
		return f.Title
	case "F-CI-COMMAND-001":
		count := 0
		for _, ev := range f.Evidence {
			if ev.Source == "ci_undocumented_command_count" {
				if n, err := strconv.Atoi(ev.Value); err == nil {
					count = n
					break
				}
			}
		}
		if count > 0 {
			return fmt.Sprintf("CI has %d undocumented commands", count)
		}
		return f.Title
	case "F-DOCKER-GPU-001":
		return "Docker GPU runtime unavailable"
	default:
		if len(f.Title) > 96 {
			return f.Title[:93] + "..."
		}
		return f.Title
	}
}
