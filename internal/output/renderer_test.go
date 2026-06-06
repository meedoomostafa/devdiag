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

func TestHumanRenderer_ShowsGpuRelatedEvidenceCollectors(t *testing.T) {
	r := &HumanRenderer{
		ColorMode:   ColorNever,
		Verbose:     true,
		HiddenCount: 0,
	}
	report := &schema.Report{
		DevDiagVersion: "1.0.0",
		Repo:           schema.RepoInfo{Root: "/test"},
		Collectors: []schema.CollectorResult{
			{Name: "gpu", Status: schema.CollectorOK, Evidence: []schema.Evidence{{Source: "gpu_count", Value: "1"}}},
			{Name: "env", Status: schema.CollectorOK, Evidence: []schema.Evidence{{Source: "env_var", Value: "1"}}},
		},
		Findings: []schema.Finding{
			{
				ID:       "F-DOCKER-GPU-001",
				Title:    "Docker GPU runtime unavailable",
				Severity: schema.SeverityHigh,
			},
		},
	}
	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "- gpu: ok") {
		t.Errorf("expected gpu collector evidence to be printed for GPU finding, got: %s", output)
	}
	if strings.Contains(output, "- env: ok") {
		t.Errorf("expected env collector evidence to be omitted since it is unrelated, got: %s", output)
	}
}

func TestHumanRenderer_ShowsUnavailableCollectorsExplicitly(t *testing.T) {
	r := &HumanRenderer{ColorMode: ColorNever}
	report := &schema.Report{
		DevDiagVersion: "1.0.0",
		Repo:           schema.RepoInfo{Root: "/test"},
		Collectors: []schema.CollectorResult{
			{Name: "env", Status: schema.CollectorOK},
			{Name: "trace", Status: schema.CollectorUnavailable, Notes: []string{"trace unavailable: strace not found"}},
			{Name: "compose", Status: schema.CollectorPartial},
			{Name: "security", Status: schema.CollectorPermissionDenied},
			{Name: "repo", Status: schema.CollectorFailed},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, want := range []string{
		"Collectors: 1 ok, 1 partial, 0 timeout, 1 unavailable, 1 permission denied, 1 failed",
		"trace: unavailable",
		"security: permission_denied",
		"repo: failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("human output missing %q:\n%s", want, output)
		}
	}
}

func TestTraceUnavailable_RendersClearStatus(t *testing.T) {
	r := &HumanRenderer{ColorMode: ColorNever}
	report := &schema.Report{
		DevDiagVersion: "1.0.0",
		Repo:           schema.RepoInfo{Root: "/test"},
		Collectors: []schema.CollectorResult{
			{
				Name:   "trace",
				Status: schema.CollectorUnavailable,
				Evidence: []schema.Evidence{
					{Source: "trace_backend", Value: "strace"},
					{Source: "trace_unavailable_reason", Value: "strace_not_found"},
					{Source: "trace_command", Value: "npm"},
				},
			},
		},
		Findings: []schema.Finding{
			{
				ID:         "F-TRACE-UNAVAILABLE-001",
				Title:      "Trace backend unavailable",
				Severity:   schema.SeverityInfo,
				Confidence: 1.0,
				Symptom:    "Syscall tracing is unavailable on this host. Reason: strace_not_found",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(report, &buf); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, want := range []string{
		"DevDiag trace unavailable",
		"Backend: strace",
		"Reason: strace_not_found",
		"Command: npm",
		"F-TRACE-UNAVAILABLE-001",
		"Install strace",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("human trace unavailable output missing %q:\n%s", want, output)
		}
	}
}

func TestMarkdownRenderer_AddsCollectorAndTraceSections(t *testing.T) {
	r := &MarkdownRenderer{HiddenCount: 2}
	report := &schema.Report{
		DevDiagVersion: "1.0.0",
		Repo:           schema.RepoInfo{Root: "/test"},
		Collectors: []schema.CollectorResult{
			{
				Name:   "trace",
				Status: schema.CollectorUnavailable,
				Evidence: []schema.Evidence{
					{Source: "trace_backend", Value: "strace"},
					{Source: "trace_unavailable_reason", Value: "strace_not_found"},
				},
				Notes: []string{"trace unavailable: strace not found"},
			},
		},
		Findings: []schema.Finding{
			{
				ID:       "F-TRACE-UNAVAILABLE-001",
				Title:    "Trace backend unavailable",
				Severity: schema.SeverityInfo,
				Evidence: []schema.Evidence{
					{Source: "trace_unavailable_reason", Value: "strace_not_found"},
				},
			},
			{
				ID:       "F-ENV-001",
				Title:    "Missing env keys",
				Severity: schema.SeverityMedium,
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
	for _, want := range []string{
		"## Collector Summary",
		"| trace | unavailable |",
		"2 hidden finding(s) are not shown",
		"## Trace Unavailable",
		"| Backend | strace |",
		"| Reason | strace_not_found |",
		"- KEY_A",
		"- KEY_B",
		"**Collector notes:**",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("markdown output missing %q:\n%s", want, output)
		}
	}
}
