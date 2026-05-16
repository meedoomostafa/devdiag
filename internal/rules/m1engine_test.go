package rules

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestM1Engine_EnvRules(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "env",
				Evidence: []schema.Evidence{
					{Source: ".env.example", Value: "keys: DATABASE_URL, API_KEY"},
					{Source: ".env", Value: "missing"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasEnv001 bool
	for _, f := range findings {
		if f.ID == "F-ENV-001" {
			hasEnv001 = true
		}
	}
	if !hasEnv001 {
		t.Errorf("expected F-ENV-001 finding, got: %v", findings)
	}
}

func TestM1Engine_RepoRules_MultipleLockfiles(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "repo",
				Evidence: []schema.Evidence{
					{Source: "lockfiles", Value: "package-lock.json, yarn.lock"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasPM001 bool
	for _, f := range findings {
		if f.ID == "F-PM-001" {
			hasPM001 = true
		}
	}
	if !hasPM001 {
		t.Errorf("expected F-PM-001 finding, got: %v", findings)
	}
}

func TestM1Engine_GitRules_TrackedEnv(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "git",
				Evidence: []schema.Evidence{
					{Source: "git_tracked_env", Value: ".env"},
					{Source: "git_env_exists", Value: "true"},
					{Source: "git_env_ignored", Value: "false"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasGit001, hasGit002 bool
	for _, f := range findings {
		if f.ID == "F-GIT-001" {
			hasGit001 = true
		}
		if f.ID == "F-GIT-002" {
			hasGit002 = true
		}
	}
	if !hasGit001 {
		t.Errorf("expected F-GIT-001 finding")
	}
	if !hasGit002 {
		t.Errorf("expected F-GIT-002 finding")
	}
}

func TestM1Engine_ComposeRules(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "compose",
				Evidence: []schema.Evidence{
					{Source: "compose.yaml:17", Value: "services.api.environment.DATABASE_URL references ${DATABASE_URL}"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasEnv002 bool
	for _, f := range findings {
		if f.ID == "F-ENV-002" {
			hasEnv002 = true
		}
	}
	if !hasEnv002 {
		t.Errorf("expected F-ENV-002 finding, got: %v", findings)
	}
}
