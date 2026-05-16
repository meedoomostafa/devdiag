package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// MarkdownRenderer emits a structured Markdown report.
type MarkdownRenderer struct{}

func (r *MarkdownRenderer) Render(report *schema.Report, w io.Writer) error {
	var b strings.Builder
	b.WriteString("# DevDiag Report\n\n")
	b.WriteString(fmt.Sprintf("**Version:** %s  \n", report.DevDiagVersion))
	b.WriteString(fmt.Sprintf("**Schema:** %s  \n", report.SchemaVersion))
	b.WriteString(fmt.Sprintf("**Run ID:** %s  \n", report.RunID))
	b.WriteString(fmt.Sprintf("**Redaction:** %s  \n\n", report.RedactionStatus))

	b.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(report.Findings)))
	for _, f := range report.Findings {
		b.WriteString(fmt.Sprintf("### %s\n\n", f.Title))
		b.WriteString(fmt.Sprintf("- **ID:** %s\n", f.ID))
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		b.WriteString(fmt.Sprintf("- **Confidence:** %.2f\n", f.Confidence))
		if f.Symptom != "" {
			b.WriteString(fmt.Sprintf("- **Symptom:** %s\n", f.Symptom))
		}
		if len(f.Evidence) > 0 {
			b.WriteString("- **Evidence:**\n")
			for _, ev := range f.Evidence {
				b.WriteString(fmt.Sprintf("  - %s: %s\n", ev.Source, ev.Value))
			}
		}
		b.WriteString("\n")
	}

	_, err := w.Write([]byte(b.String()))
	return err
}
