package output
 
import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// HumanRenderer emits terminal-friendly output with optional color.
type HumanRenderer struct {
	ColorMode   ColorMode
	Verbose     bool
	HiddenCount int
}

type collectorSummary struct {
	OK, Partial, Timeout, Unavailable, Failed, PermissionDenied int
}

func summarizeCollectors(report *schema.Report) collectorSummary {
	var s collectorSummary
	for _, c := range report.Collectors {
		switch c.Status {
		case schema.CollectorOK, "":
			s.OK++
		case schema.CollectorPartial:
			s.Partial++
		case schema.CollectorTimeout:
			s.Timeout++
		case schema.CollectorUnavailable:
			s.Unavailable++
		case schema.CollectorFailed:
			s.Failed++
		case schema.CollectorPermissionDenied:
			s.PermissionDenied++
		default:
			s.OK++
		}
	}
	return s
}

func highestSeverity(findings []schema.Finding) schema.Severity {
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

func summarizeFindingTitle(f schema.Finding) string {
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

func suggestedNextCommand(f schema.Finding) string {
	switch f.ID {
	case "F-ENV-001", "F-ENV-001-OPTIONAL":
		return "devdiag inspect . --filter env"
	case "F-CI-ENV-001", "F-CI-ENV-DEPLOY-INFO", "F-CI-COMMAND-001":
		return "devdiag inspect . --filter ci"
	default:
		id := strings.ToUpper(f.ID)
		if strings.Contains(id, "-ENV-") {
			return "devdiag inspect . --filter env"
		}
		if strings.Contains(id, "-CI-") {
			return "devdiag inspect . --filter ci"
		}
		if strings.Contains(id, "-CONTAINER-") || strings.Contains(id, "-DOCKER-") || strings.Contains(id, "-PODMAN-") {
			return "devdiag inspect . --filter containers"
		}
		if strings.Contains(id, "-RUNTIME-") {
			return "devdiag inspect . --filter runtime"
		}
		if strings.Contains(id, "-GPU-") {
			return "devdiag inspect . --filter gpu"
		}
		if strings.Contains(id, "-TRACE-") {
			return "devdiag inspect . --filter trace"
		}
		return "devdiag inspect ."
	}
}

func hasUnavailableCollectors(collectors []schema.CollectorResult) bool {
	for _, c := range collectors {
		if c.Status == schema.CollectorUnavailable || c.Status == schema.CollectorFailed || c.Status == schema.CollectorPermissionDenied {
			return true
		}
	}
	return false
}

func renderCollectorIssues(collectors []schema.CollectorResult, b *strings.Builder) {
	b.WriteString("Collector Issues:\n")
	for _, c := range collectors {
		if c.Status == schema.CollectorUnavailable || c.Status == schema.CollectorFailed || c.Status == schema.CollectorPermissionDenied {
			b.WriteString(fmt.Sprintf("  - %s: %s\n", c.Name, c.Status))
			for _, note := range c.Notes {
				b.WriteString(fmt.Sprintf("    Note: %s\n", note))
			}
		}
	}
	b.WriteString("\n")
}

func relatedCollectorsForFinding(f schema.Finding) []string {
	id := strings.ToUpper(f.ID)
	if strings.Contains(id, "-GPU-") {
		return []string{"gpu", "cuda", "gpudocker", "docker"}
	}
	if strings.Contains(id, "-ML-") {
		return []string{"python_ml", "gpu", "cuda"}
	}
	if strings.Contains(id, "-CACHE-") {
		return []string{"cache"}
	}
	if strings.Contains(id, "-ENV-") {
		return []string{"env", "config"}
	}
	if strings.Contains(id, "-CI-") {
		return []string{"ci", "config"}
	}
	if strings.Contains(id, "-PORT-") {
		return []string{"port", "compose"}
	}
	if strings.Contains(id, "-DOCKER-") {
		return []string{"docker"}
	}
	if strings.Contains(id, "-PODMAN-") {
		return []string{"podman"}
	}
	if strings.Contains(id, "-PM-") {
		return []string{"repo"}
	}
	if strings.Contains(id, "-RUNTIME-") {
		return []string{"runtime", "host_runtime"}
	}
	if strings.Contains(id, "-GIT-") {
		return []string{"git"}
	}
	if strings.Contains(id, "-DISK-") {
		return []string{"disk"}
	}
	if strings.Contains(id, "-NET-") {
		return []string{"network"}
	}
	if strings.Contains(id, "-SVC-") {
		return []string{"systemd"}
	}
	if strings.Contains(id, "-SEC-") {
		return []string{"security"}
	}
	if strings.Contains(id, "-FS-") || strings.Contains(id, "-PERM-") {
		return []string{"permission"}
	}
	if strings.Contains(id, "-TRACE-") {
		return []string{"trace"}
	}
	return nil
}

func (r *HumanRenderer) Render(report *schema.Report, w io.Writer) error {
	useColor := ShouldColor(r.ColorMode, IsTTY(os.Stdout))

	var b strings.Builder
	b.WriteString(fmt.Sprintf("DevDiag %s — scan completed\n", report.DevDiagVersion))
	b.WriteString(fmt.Sprintf("Repo: %s\n", report.Repo.Root))
	if report.Host.OS != "" {
		b.WriteString(fmt.Sprintf("Host: %s %s | kernel %s | shell %s\n",
			report.Host.OS, report.Host.Version, report.Host.Kernel, report.Host.Session))
	}
	b.WriteString("\n")

	cSummary := summarizeCollectors(report)
	b.WriteString("Summary\n")
	b.WriteString(fmt.Sprintf("  Findings: %d actionable, %d hidden\n", len(report.Findings), r.HiddenCount))
	b.WriteString(fmt.Sprintf("  Collectors: %d ok, %d partial, %d failed\n",
		cSummary.OK, cSummary.Partial+cSummary.Timeout+cSummary.Unavailable+cSummary.PermissionDenied, cSummary.Failed))
	b.WriteString(fmt.Sprintf("  Highest severity: %s\n\n", highestSeverity(report.Findings)))

	if len(report.Findings) > 0 {
		heading := "Actionable findings"
		if containsLowVisibilityFinding(report.Findings) && r.HiddenCount == 0 {
			heading = "Findings"
		}
		b.WriteString(fmt.Sprintf("%s\n", heading))
		for i, f := range report.Findings {
			label := fmt.Sprintf("[%s]", f.Severity)
			if useColor {
				label = colorizeSeverity(string(f.Severity), label)
			}
			title := summarizeFindingTitle(f)
			b.WriteString(fmt.Sprintf("  %d. %-12s %s  %s\n", i+1, label, f.ID, title))
			if f.Symptom != "" {
				b.WriteString(fmt.Sprintf("     Why: %s\n", f.Symptom))
			}
			b.WriteString(fmt.Sprintf("     Next: %s\n", suggestedNextCommand(f)))
			b.WriteString("\n")
		}
	} else if r.HiddenCount > 0 {
		b.WriteString("No actionable findings at the default visibility level.\n\n")
	} else {
		b.WriteString("No findings.\n\n")
	}

	if hasUnavailableCollectors(report.Collectors) {
		renderCollectorIssues(report.Collectors, &b)
	}

	b.WriteString(fmt.Sprintf("Run ID: %s\n", report.RunID))
	b.WriteString(fmt.Sprintf("Redaction: %s\n", report.RedactionStatus))
	if r.HiddenCount > 0 {
		b.WriteString(fmt.Sprintf("Hidden: %d low/info or suppressed finding(s). Re-run with --include-hidden to show them.\n", r.HiddenCount))
	}
	if report.RedactionStatus == "off" {
		b.WriteString("WARNING: redaction is disabled. Secrets may be visible.\n")
	}
	b.WriteString("Use --verbose for evidence. Use 'devdiag inspect .' for interactive view.\n")

	if r.Verbose && len(report.Collectors) > 0 {
		b.WriteString("\nCollector evidence\n")
		for _, c := range report.Collectors {
			statusStr := string(c.Status)
			if statusStr == "" {
				statusStr = "ok"
			}
			b.WriteString(fmt.Sprintf("  %-11s %-8s %d evidence\n", c.Name, statusStr, len(c.Evidence)))
		}

		related := make(map[string]bool)
		for _, f := range report.Findings {
			for _, rc := range relatedCollectorsForFinding(f) {
				related[rc] = true
			}
		}

		b.WriteString("\nDetailed evidence for active findings:\n")
		printedAny := false
		for _, c := range report.Collectors {
			if !related[c.Name] {
				continue
			}
			printedAny = true
			statusStr := string(c.Status)
			if statusStr == "" {
				statusStr = "ok"
			}
			b.WriteString(fmt.Sprintf("- %s: %s\n", c.Name, statusStr))
			for _, ev := range c.Evidence {
				b.WriteString(fmt.Sprintf("  %s=%s\n", ev.Source, ev.Value))
			}
			for _, note := range c.Notes {
				b.WriteString(fmt.Sprintf("  note=%s\n", note))
			}
		}
		if !printedAny {
			b.WriteString("  No active findings requiring detailed collector evidence.\n")
		}
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

func containsLowVisibilityFinding(findings []schema.Finding) bool {
	for _, f := range findings {
		if f.Severity == schema.SeverityLow || f.Severity == schema.SeverityInfo {
			return true
		}
	}
	return false
}

var severityColors = map[string]string{
	"critical": "\033[31m", // red
	"high":     "\033[33m", // yellow
	"medium":   "\033[35m", // magenta
	"low":      "\033[36m", // cyan
	"info":     "\033[34m", // blue
}

const resetColor = "\033[0m"

func colorizeSeverity(severity, text string) string {
	c, ok := severityColors[severity]
	if !ok {
		return text
	}
	return c + text + resetColor
}
