package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// GitHubRenderer emits GitHub Actions workflow commands (::error::, ::warning::).
type GitHubRenderer struct{}

func (r *GitHubRenderer) Render(report *schema.Report, w io.Writer) error {
	for _, f := range report.Findings {
		if f.Severity == schema.SeverityCritical || f.Severity == schema.SeverityHigh {
			renderGitHubAnnotation(w, "error", f)
		} else if f.Severity == schema.SeverityMedium {
			renderGitHubAnnotation(w, "warning", f)
		}
	}
	return nil
}

func renderGitHubAnnotation(w io.Writer, level string, f schema.Finding) {
	title := escapeGHProperty(f.ID)
	msg := escapeGHData(f.Title)
	if f.Symptom != "" {
		msg += ": " + escapeGHData(f.Symptom)
	}
	fmt.Fprintf(w, "::%s title=%s::%s\n", level, title, msg)
}

func escapeGHData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func escapeGHProperty(s string) string {
	s = escapeGHData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}
