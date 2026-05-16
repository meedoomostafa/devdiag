package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// HumanRenderer emits terminal-friendly output with optional color.
type HumanRenderer struct {
	ColorMode ColorMode
}

func (r *HumanRenderer) Render(report *schema.Report, w io.Writer) error {
	useColor := ShouldColor(r.ColorMode, IsTTY(os.Stdout))

	var b strings.Builder
	b.WriteString(fmt.Sprintf("DevDiag %s — scan completed\n", report.DevDiagVersion))
	b.WriteString(fmt.Sprintf("repo: %s\n", report.Repo.Root))
	b.WriteString(fmt.Sprintf("host: %s %s, kernel %s, session=%s\n",
		report.Host.OS, report.Host.Version, report.Host.Kernel, report.Host.Session))
	b.WriteString("\n")

	if len(report.Findings) > 0 {
		b.WriteString("Top findings\n")
		for _, f := range report.Findings {
			label := fmt.Sprintf("[%s]", f.Severity)
			if useColor {
				label = colorizeSeverity(string(f.Severity), label)
			}
			b.WriteString(fmt.Sprintf("%-12s %s  %s  confidence=%.2f\n",
				label, f.ID, f.Title, f.Confidence))
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("Run ID: %s\n", report.RunID))
	b.WriteString(fmt.Sprintf("Redaction: %s\n", report.RedactionStatus))
	if report.RedactionStatus == "off" {
		b.WriteString("WARNING: redaction is disabled. Secrets may be visible.\n")
	}

	_, err := w.Write([]byte(b.String()))
	return err
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
