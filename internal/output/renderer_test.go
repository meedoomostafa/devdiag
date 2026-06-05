package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestHumanRenderer_CompactsLongFindingTitles(t *testing.T) {
	r := &HumanRenderer{
		ColorMode:   ColorNever,
		Verbose:     false,
		HiddenCount: 2,
	}

	report := &schema.Report{
		DevDiagVersion: "1.0.0",
		Repo:           schema.RepoInfo{Root: "/test"},
		Collectors: []schema.CollectorResult{
			{Name: "env", Status: schema.CollectorOK},
		},
		Findings: []schema.Finding{
			{
				ID:       "F-ENV-001",
				Title:    "Missing env keys: extremely_long_key_name_that_goes_on_and_on_to_explode_title",
				Severity: schema.SeverityMedium,
				Symptom:  "Required variables are missing from .env",
				Evidence: []schema.Evidence{
					{Source: "missing_keys", Value: "KEY_A, KEY_B, KEY_C"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "3 env keys missing from .env") {
		t.Errorf("expected title to be summarized, got: %s", output)
	}
	if !strings.Contains(output, "Why: Required variables are missing from .env") {
		t.Errorf("expected symptom in output, got: %s", output)
	}
	if !strings.Contains(output, "Next: devdiag inspect . --filter env") {
		t.Errorf("expected next action suggestion, got: %s", output)
	}
}

func TestMarkdownRenderer_UsesSummaryAndDetails(t *testing.T) {
	r := &MarkdownRenderer{
		HiddenCount: 3,
	}

	report := &schema.Report{
		DevDiagVersion: "1.0.0",
		Repo:           schema.RepoInfo{Root: "/test"},
		Findings: []schema.Finding{
			{
				ID:       "F-ENV-001",
				Title:    "Missing env keys: KEY_A",
				Severity: schema.SeverityMedium,
				Symptom:  "Required variables are missing from .env",
				Evidence: []schema.Evidence{
					{Source: "missing_keys", Value: "KEY_A, KEY_B"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "| Findings | 1 actionable, 3 hidden |") {
		t.Errorf("expected summary table, got: %s", output)
	}
	if !strings.Contains(output, "<details>") || !strings.Contains(output, "</details>") {
		t.Errorf("expected collapsible details tags, got: %s", output)
	}
	if !strings.Contains(output, "<summary>F-ENV-001 — 2 env keys missing from .env</summary>") {
		t.Errorf("expected structured summary tag, got: %s", output)
	}
}
