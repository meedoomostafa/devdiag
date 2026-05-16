package rules

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func assertFindingM8(t *testing.T, findings []schema.Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return
		}
	}
	t.Errorf("expected finding %s, got none", id)
}

func TestM8Engine_RuntimeMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__1__setup_node__node_version", Value: "20"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: ".nvmrc", Value: "node 22"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-RUNTIME-001")
}

func TestM8Engine_MissingLocalRuntimePin(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__1__setup_go__go_version", Value: "1.22"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-PACKAGE-001")
}

func TestM8Engine_EnvMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__API_KEY", Value: "${{ secrets.API_KEY }}"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env.example", Value: "keys: OTHER_KEY"},
				{Source: ".env", Value: "keys: OTHER_KEY"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-ENV-001")
}

func TestM8Engine_ServicePortMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__test__postgres__host_port", Value: "5432"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_host_port", Value: "3000"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-SERVICE-001")
}

func TestM8Engine_ContainerDrift(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_container__test__image", Value: "node:20-alpine"},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "devcontainer_image", Value: "mcr.microsoft.com/devcontainers/javascript-node:22"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-CONTAINER-001")
}

func TestM8Engine_ShellMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_defaults__job__test__shell", Value: "bash"},
			}},
			{Name: "host", Evidence: []schema.Evidence{
				{Source: "host_shell", Value: "zsh"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-SHELL-001")
}

func TestM8Engine_JobEnvKeyExtraction(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__API_KEY", Value: "${{ secrets.API_KEY }}"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: OTHER_KEY"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-ENV-001")
	// Ensure finding references the correct key
	for _, f := range findings {
		if f.ID == "F-CI-ENV-001" {
			if !strings.Contains(f.Title, "API_KEY") {
				t.Errorf("expected finding title to reference API_KEY, got: %s", f.Title)
			}
		}
	}
}

func TestM8Engine_StepEnvKeyExtraction(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__step__test__0__STEP_KEY", Value: "value"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: OTHER_KEY"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-ENV-001")
	for _, f := range findings {
		if f.ID == "F-CI-ENV-001" {
			if !strings.Contains(f.Title, "STEP_KEY") {
				t.Errorf("expected finding title to reference STEP_KEY, got: %s", f.Title)
			}
		}
	}
}

func TestM8Engine_ServicePortMismatch_NewSourceSchema(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__test__postgres__host_port", Value: "5432"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_host_port", Value: "3000"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-SERVICE-001")
}

func TestM8Engine_MultipleJobContainers(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_container__test__image", Value: "node:20-alpine"},
				{Source: "ci_container__build__image", Value: "golang:1.22"},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "devcontainer_image", Value: "mcr.microsoft.com/devcontainers/javascript-node:22"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// At least one container should trigger a drift finding
	var containerFindings int
	for _, f := range findings {
		if f.ID == "F-CI-CONTAINER-001" {
			containerFindings++
		}
	}
	if containerFindings == 0 {
		t.Error("expected at least one F-CI-CONTAINER-001 finding for multiple job containers")
	}
}

func TestM8Engine_NoCINoFindings(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: ".nvmrc", Value: "node 20"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings without CI evidence, got %d", len(findings))
	}
}
