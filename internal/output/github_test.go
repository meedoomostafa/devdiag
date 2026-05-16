package output

import (
"bytes"
"strings"
"testing"

"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestGitHubRenderer_EmitsErrorForHighSeverity(t *testing.T) {
	r := &GitHubRenderer{}
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-TEST-001", Title: "Test high", Severity: schema.SeverityHigh, Symptom: "broken"},
		},
	}
	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "::error title=F-TEST-001::") {
		t.Errorf("expected error annotation, got: %s", out)
	}
}

func TestGitHubRenderer_EmitsWarningForMediumSeverity(t *testing.T) {
	r := &GitHubRenderer{}
	report := &schema.Report{
		Findings: []schema.Finding{
			{ID: "F-TEST-002", Title: "Test medium", Severity: schema.SeverityMedium, Symptom: "warn"},
		},
	}
	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "::warning title=F-TEST-002::") {
		t.Errorf("expected warning annotation, got: %s", out)
	}
}

func TestGitHubRenderer_EscapesWorkflowCommandDataAndProperties(t *testing.T) {
	r := &GitHubRenderer{}
	report := &schema.Report{
		Findings: []schema.Finding{
			{
				ID:       "F-TEST:001,ABC",
				Title:    "bad % title",
				Severity: schema.SeverityHigh,
				Symptom:  "line1\r\nline2",
			},
		},
	}
	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, raw := range []string{"line1\n", "line1\r", "F-TEST:001,ABC"} {
		if strings.Contains(out, raw) {
			t.Fatalf("expected raw value %q to be escaped in %q", raw, out)
		}
	}
	for _, escaped := range []string{"%25", "%0D", "%0A", "%3A", "%2C"} {
		if !strings.Contains(out, escaped) {
			t.Fatalf("expected %s in escaped output: %q", escaped, out)
		}
	}
}
