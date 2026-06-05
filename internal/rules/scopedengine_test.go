package rules

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

type mockEngine struct {
	findings []schema.Finding
}

func (m *mockEngine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	return m.findings, nil
}

func TestScopedEngineFiltersPrefixes(t *testing.T) {
	mock := &mockEngine{
		findings: []schema.Finding{
			{ID: "F-ENV-001"},
			{ID: "F-PORT-001"},
			{ID: "f-env-002"}, // case insensitivity check
		},
	}
	engine := NewScopedEngine(mock, "F-ENV-")
	res, err := engine.Evaluate(graph.NormalizedSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 filtered findings, got %d", len(res))
	}
	if res[0].ID != "F-ENV-001" || res[1].ID != "f-env-002" {
		t.Errorf("unexpected findings: %+v", res)
	}
}

func TestCompositeScopedEngineFiltersPrefixes(t *testing.T) {
	mock1 := &mockEngine{findings: []schema.Finding{{ID: "F-ENV-001"}}}
	mock2 := &mockEngine{findings: []schema.Finding{{ID: "F-PORT-001"}}}

	engine := NewCompositeScopedEngine([]PolicyEngine{mock1, mock2}, "F-ENV-", "F-PORT-")
	res, err := engine.Evaluate(graph.NormalizedSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res))
	}
}

func TestEnvEnginePrefixes(t *testing.T) {
	engine := NewEnvEngine()
	se, ok := engine.(*ScopedEngine)
	if !ok {
		t.Fatal("expected ScopedEngine type")
	}
	if len(se.prefixes) != 1 || se.prefixes[0] != "F-ENV-" {
		t.Errorf("unexpected prefixes: %v", se.prefixes)
	}
}

func TestPortEnginePrefixes(t *testing.T) {
	engine := NewPortEngine()
	se, ok := engine.(*ScopedEngine)
	if !ok {
		t.Fatal("expected ScopedEngine type")
	}
	if len(se.prefixes) != 1 || se.prefixes[0] != "F-PORT-" {
		t.Errorf("unexpected prefixes: %v", se.prefixes)
	}
}

func TestContainerEngineWithoutGPUFiltersGPUFindings(t *testing.T) {
	mock1 := &mockEngine{
		findings: []schema.Finding{
			{ID: "F-CONTAINER-001"},
			{ID: "F-DOCKER-001"},
			{ID: "F-GPU-001"},
		},
	}
	engine := NewContainerEngine(false)
	se, ok := engine.(*ScopedEngine)
	if !ok {
		t.Fatal("expected ScopedEngine type")
	}
	
	testEngine := NewScopedEngine(mock1, se.prefixes...)
	res, err := testEngine.Evaluate(graph.NormalizedSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res))
	}
	for _, f := range res {
		if f.ID == "F-GPU-001" {
			t.Error("GPU finding should be filtered out without GPU mode")
		}
	}
}

func TestContainerEngineWithGPUAllowsGPUFindings(t *testing.T) {
	engine := NewContainerEngine(true)
	se, ok := engine.(*ScopedEngine)
	if !ok {
		t.Fatal("expected ScopedEngine type")
	}
	
	hasGPU := false
	for _, p := range se.prefixes {
		if p == "F-GPU-" {
			hasGPU = true
		}
	}
	if !hasGPU {
		t.Error("expected F-GPU- to be included in ContainerEngine(true)")
	}
}

func TestContainerEngineWithGPUAllowsDockerGPUFindings(t *testing.T) {
	mock := &mockEngine{
		findings: []schema.Finding{
			{ID: "F-GPU-001"},
			{ID: "F-DOCKER-GPU-001"},
			{ID: "F-CACHE-001"},
			{ID: "F-ML-PYTORCH-001"},
		},
	}
	engine := NewContainerEngine(true)
	se, ok := engine.(*ScopedEngine)
	if !ok {
		t.Fatal("expected ScopedEngine type")
	}

	testEngine := NewScopedEngine(mock, se.prefixes...)
	res, err := testEngine.Evaluate(graph.NormalizedSnapshot{})
	if err != nil {
		t.Fatal(err)
	}

	var allowed, blocked []string
	for _, f := range res {
		allowed = append(allowed, f.ID)
	}
	
	for _, f := range mock.findings {
		found := false
		for _, a := range allowed {
			if a == f.ID {
				found = true
				break
			}
		}
		if !found {
			blocked = append(blocked, f.ID)
		}
	}

	if len(allowed) != 2 {
		t.Fatalf("expected exactly 2 allowed findings, got %d (%v)", len(allowed), allowed)
	}
	for _, a := range allowed {
		if a != "F-GPU-001" && a != "F-DOCKER-GPU-001" {
			t.Errorf("unexpected allowed finding: %s", a)
		}
	}
	for _, b := range blocked {
		if b != "F-CACHE-001" && b != "F-ML-PYTORCH-001" {
			t.Errorf("unexpected blocked finding: %s", b)
		}
	}
}

func TestGitEngineAllowsPackageManagerFindings(t *testing.T) {
	engine := NewGitEngine()
	se, ok := engine.(*ScopedEngine)
	if !ok {
		t.Fatal("expected ScopedEngine type")
	}

	hasGit := false
	hasPM := false
	for _, p := range se.prefixes {
		if p == "F-GIT-" {
			hasGit = true
		}
		if p == "F-PM-" {
			hasPM = true
		}
	}
	if !hasGit || !hasPM {
		t.Errorf("expected F-GIT- and F-PM- in GitEngine, got %v", se.prefixes)
	}
}
