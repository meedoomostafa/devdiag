package fix

import (
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func makeTestReport(findings []schema.Finding) *schema.Report {
	return &schema.Report{
		SchemaVersion: "0.1",
		RunID:         "test-run",
		Repo:          schema.RepoInfo{Root: "/tmp/repo"},
		Findings:      findings,
		Collectors:    []schema.CollectorResult{},
	}
}

func TestPlannerResolve(t *testing.T) {
	report := makeTestReport([]schema.Finding{
		{
			ID:       "F-FS-001",
			Title:    "Script missing executable bit: script.sh",
			FixHints: []string{"chmod-script"},
			Evidence: []schema.Evidence{
				{Source: "host_script_not_executable", Value: "script.sh"},
			},
		},
	})

	planner := NewPlanner()
	proposals, err := planner.Resolve(report, ResolveOptions{
		FindingID: "F-FS-001",
		Source:    schema.FixSourceSavedReport,
		RunID:     "test-run",
		ReportAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(proposals))
	}
	if proposals[0].HintID != "chmod-script" {
		t.Fatalf("expected chmod-script, got %q", proposals[0].HintID)
	}
	if proposals[0].Class != schema.FixSafe {
		t.Fatalf("expected safe class, got %q", proposals[0].Class)
	}
	if proposals[0].Source != schema.FixSourceSavedReport {
		t.Fatalf("expected saved_report source, got %q", proposals[0].Source)
	}
}

func TestPlannerResolveMissingFinding(t *testing.T) {
	report := makeTestReport([]schema.Finding{})
	planner := NewPlanner()
	_, err := planner.Resolve(report, ResolveOptions{FindingID: "F-FS-001"})
	if err == nil {
		t.Fatal("expected error for missing finding")
	}
}

func TestPlannerResolveNoHints(t *testing.T) {
	report := makeTestReport([]schema.Finding{
		{ID: "F-OTHER-001", Title: "Other"},
	})
	planner := NewPlanner()
	proposals, err := planner.Resolve(report, ResolveOptions{FindingID: "F-OTHER-001"})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(proposals) != 0 {
		t.Fatalf("expected 0 proposals, got %d", len(proposals))
	}
}

func TestPlannerStaleness(t *testing.T) {
	report := makeTestReport([]schema.Finding{
		{
			ID:       "F-FS-001",
			FixHints: []string{"chmod-script"},
			Evidence: []schema.Evidence{
				{Source: "host_script_not_executable", Value: "script.sh"},
			},
		},
	})
	planner := NewPlanner()

	// 40 minutes old -> warn
	proposals, err := planner.Resolve(report, ResolveOptions{
		FindingID: "F-FS-001",
		Source:    schema.FixSourceSavedReport,
		ReportAge: 40 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if proposals[0].StalenessWarn == "" {
		t.Fatal("expected staleness warning")
	}

	// 1 minute old -> no warn
	proposals, err = planner.Resolve(report, ResolveOptions{
		FindingID: "F-FS-001",
		Source:    schema.FixSourceSavedReport,
		ReportAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if proposals[0].StalenessWarn != "" {
		t.Fatalf("unexpected staleness warning: %s", proposals[0].StalenessWarn)
	}
}

func TestPlannerListAll(t *testing.T) {
	report := makeTestReport([]schema.Finding{
		{
			ID:       "F-FS-001",
			FixHints: []string{"chmod-script"},
			Evidence: []schema.Evidence{
				{Source: "host_script_not_executable", Value: "script.sh"},
			},
		},
		{
			ID:       "F-GIT-001",
			FixHints: []string{"gitignore-env"},
			Evidence: []schema.Evidence{
				{Source: "git_tracked_env", Value: ".env"},
				{Source: "git_env_exists", Value: "true"},
			},
		},
	})
	planner := NewPlanner()
	proposals, err := planner.ListAll(report, schema.FixSourceSavedReport, "test-run", time.Minute)
	if err != nil {
		t.Fatalf("ListAll error: %v", err)
	}
	if len(proposals) != 2 {
		t.Fatalf("expected 2 proposals, got %d", len(proposals))
	}
}

func TestRankProposals(t *testing.T) {
	proposals := []schema.FixProposal{
		{HintID: "manual", Class: schema.FixManual},
		{HintID: "safe", Class: schema.FixSafe},
		{HintID: "blocked", Class: schema.FixBlocked},
		{HintID: "guarded", Class: schema.FixGuarded},
	}
	ranked := rankProposals(proposals)
	expected := []schema.FixClass{schema.FixSafe, schema.FixGuarded, schema.FixManual, schema.FixBlocked}
	for i, want := range expected {
		if ranked[i].Class != want {
			t.Fatalf("rankProposals[%d].Class = %q, want %q", i, ranked[i].Class, want)
		}
	}
}
