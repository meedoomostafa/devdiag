package fix

import (
	"fmt"
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

func TestPlannerResolveComposeUpGuardedWithRollback(t *testing.T) {
	report := makeTestReport([]schema.Finding{
		{
			ID:       "F-CONTAINER-001",
			Title:    "Compose service 'api' is not running",
			FixHints: []string{"compose-up"},
			Evidence: []schema.Evidence{
				{Source: "compose_service_api_status", Value: "exited"},
			},
		},
	})

	planner := NewPlanner()
	proposals, err := planner.Resolve(report, ResolveOptions{
		FindingID: "F-CONTAINER-001",
		Source:    schema.FixSourceSavedReport,
		RunID:     "test-run",
		ReportAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %d: %+v", len(proposals), proposals)
	}
	got := proposals[0]
	if got.HintID != "compose-up" {
		t.Fatalf("HintID = %q, want compose-up", got.HintID)
	}
	if got.Class != schema.FixGuarded {
		t.Fatalf("Class = %q, want guarded", got.Class)
	}
	if got.Bin != "docker" {
		t.Fatalf("Bin = %q, want docker", got.Bin)
	}
	wantArgs := []string{"compose", "--project-directory", "/tmp/repo", "up", "-d", "api"}
	if len(got.Args) != len(wantArgs) {
		t.Fatalf("Args = %v, want %v", got.Args, wantArgs)
	}
	for i := range wantArgs {
		if got.Args[i] != wantArgs[i] {
			t.Fatalf("Args = %v, want %v", got.Args, wantArgs)
		}
	}
	wantRollback := []string{"docker", "compose", "--project-directory", "/tmp/repo", "stop", "api"}
	if len(got.Rollback) != len(wantRollback) {
		t.Fatalf("Rollback = %v, want %v", got.Rollback, wantRollback)
	}
	for i := range wantRollback {
		if got.Rollback[i] != wantRollback[i] {
			t.Fatalf("Rollback = %v, want %v", got.Rollback, wantRollback)
		}
	}
	if got.ConfirmMessage == "" {
		t.Fatal("guarded compose-up proposal missing confirm message")
	}
}

func TestPlannerSkipsGuardedComposeUpForInvalidServiceEvidence(t *testing.T) {
	report := makeTestReport([]schema.Finding{
		{
			ID:       "F-CONTAINER-001",
			Title:    "Compose service has unsafe evidence",
			FixHints: []string{"compose-up"},
			Evidence: []schema.Evidence{
				{Source: "compose_service_api;rm_status", Value: "exited"},
			},
		},
	})

	planner := NewPlanner()
	proposals, err := planner.Resolve(report, ResolveOptions{
		FindingID: "F-CONTAINER-001",
		Source:    schema.FixSourceSavedReport,
		RunID:     "test-run",
		ReportAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(proposals) != 0 {
		t.Fatalf("expected invalid compose service evidence to produce no guarded proposal, got %+v", proposals)
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

func TestPlannerResolveRelativeRoot(t *testing.T) {
	report := &schema.Report{
		SchemaVersion: "0.1",
		RunID:         "test-run",
		Repo:          schema.RepoInfo{Root: "."},
		Findings: []schema.Finding{
			{
				ID:       "F-FS-001",
				Title:    "Script missing executable bit: script.sh",
				FixHints: []string{"chmod-script"},
				Evidence: []schema.Evidence{
					{Source: "host_script_not_executable", Value: "script.sh"},
				},
			},
		},
		Collectors: []schema.CollectorResult{},
	}

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
}

func TestPlannerResolveEmptyRoot(t *testing.T) {
	report := &schema.Report{
		SchemaVersion: "0.1",
		RunID:         "test-run",
		Repo:          schema.RepoInfo{Root: ""},
		Findings: []schema.Finding{
			{
				ID:       "F-FS-001",
				Title:    "Script missing executable bit: script.sh",
				FixHints: []string{"chmod-script"},
				Evidence: []schema.Evidence{
					{Source: "host_script_not_executable", Value: "script.sh"},
				},
			},
		},
		Collectors: []schema.CollectorResult{},
	}

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
}

func TestPlannerResolveWithDebugLog(t *testing.T) {
	report := &schema.Report{
		SchemaVersion: "0.1",
		RunID:         "test-run",
		Repo:          schema.RepoInfo{Root: "/tmp/repo"},
		Findings: []schema.Finding{
			{
				ID:       "F-FS-001",
				Title:    "Script missing executable bit: script.sh",
				FixHints: []string{"invalid-hint-id"},
			},
		},
		Collectors: []schema.CollectorResult{},
	}

	planner := NewPlanner()
	var logged string
	proposals, err := planner.Resolve(report, ResolveOptions{
		FindingID: "F-FS-001",
		Source:    schema.FixSourceSavedReport,
		RunID:     "test-run",
		ReportAge: time.Minute,
		DebugLog: func(format string, args ...interface{}) {
			logged = fmt.Sprintf(format, args...)
		},
	})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(proposals) != 0 {
		t.Fatalf("expected 0 proposals, got %d", len(proposals))
	}
	if logged == "" {
		t.Fatal("expected debug log callback to be invoked for skipped template")
	}
}

func TestPlannerResolveTildeRoot(t *testing.T) {
	report := &schema.Report{
		SchemaVersion: "0.1",
		RunID:         "test-run",
		Repo:          schema.RepoInfo{Root: "~/test-repo-path"},
		Findings: []schema.Finding{
			{
				ID:       "F-FS-001",
				Title:    "Script missing executable bit: script.sh",
				FixHints: []string{"chmod-script"},
				Evidence: []schema.Evidence{
					{Source: "host_script_not_executable", Value: "script.sh"},
				},
			},
		},
		Collectors: []schema.CollectorResult{},
	}

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
}


