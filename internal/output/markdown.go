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
				maxEv := 5
				for idx, ev := range f.Evidence {
					if idx >= maxEv {
						b.WriteString(fmt.Sprintf("- and %d more\n", len(f.Evidence)-maxEv))
						break
					}
					val := ev.Value
					// Truncate overly long evidence lines to keep markdown neat
					if len(val) > 200 {
						val = val[:197] + "..."
					}
					b.WriteString(fmt.Sprintf("- `%s`: %s\n", ev.Source, val))
				}
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
	case "F-ENV-001":
		count := 0
		for _, ev := range f.Evidence {
			if ev.Source == "missing_keys" || ev.Source == "missing_optional_keys" {
				if parts := strings.Split(ev.Value, ", "); len(parts) > 0 && ev.Value != "" {
					count += len(parts)
				}
			}
		}
		if count > 0 {
			if strings.Contains(strings.ToLower(f.Title), "optional") {
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
