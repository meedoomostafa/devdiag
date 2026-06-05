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

func assertNoFindingM8(t *testing.T, findings []schema.Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			t.Fatalf("expected no finding %s, got %+v", id, f)
		}
	}
}

func countFindingM8(findings []schema.Finding, id string) int {
	count := 0
	for _, f := range findings {
		if f.ID == id {
			count++
		}
	}
	return count
}

func assertFindingEvidenceValueM8(t *testing.T, finding schema.Finding, value string) {
	t.Helper()
	for _, ev := range finding.Evidence {
		if ev.Value == value {
			return
		}
	}
	t.Fatalf("expected finding %s to include evidence value %q, got %+v", finding.ID, value, finding.Evidence)
}

func assertFindingEvidenceAbsentM8(t *testing.T, finding schema.Finding, value string) {
	t.Helper()
	for _, ev := range finding.Evidence {
		if ev.Value == value {
			t.Fatalf("expected finding %s not to include evidence value %q, got %+v", finding.ID, value, finding.Evidence)
		}
	}
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

func TestM8Engine_EnvLocalSatisfiesCIEnvKey(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__API_KEY", Value: "local-dev-value"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env.local", Value: "keys: API_KEY"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-ENV-001")
}

func TestM8Engine_GitHubBuiltInEnvIgnored(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__GITHUB_TOKEN", Value: "${{ github.token }}"},
			}},
			{Name: "env", Evidence: []schema.Evidence{}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-ENV-001")
}

func TestM8Engine_StandardCIControlEnvIgnored(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__workflow__NODE_ENV", Value: "production"},
				{Source: "ci_env__workflow__DOTNET_NOLOGO", Value: "true"},
				{Source: "ci_env__workflow__DOTNET_CLI_TELEMETRY_OPTOUT", Value: "1"},
				{Source: "ci_env__workflow__DOTNET_VERSION", Value: "10.0.x"},
			}},
			{Name: "env", Evidence: []schema.Evidence{}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-ENV-001")
}

func TestM8Engine_EnvLocalOnlyDoesNotRequireCI(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "npm test"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env.local", Value: "keys: LOCAL_ONLY"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-ENV-002")
}

func TestM8Engine_EnvExampleDoesNotRequireCI(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "npm test"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env.example", Value: "keys: API_KEY, SERVICE_URL"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-ENV-002")
}

func TestM8Engine_RealEnvStillWarnsWhenMissingFromCI(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "npm test"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: SERVICE_URL"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-ENV-002")
}

func TestM8Engine_EnvMissingKeysAreGrouped(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__CI_ONLY_A", Value: "value"},
				{Source: "ci_env__job__test__CI_ONLY_B", Value: "value"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: LOCAL_ONLY_A, LOCAL_ONLY_B"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got := countFindingM8(findings, "F-CI-ENV-001"); got != 1 {
		t.Fatalf("F-CI-ENV-001 count = %d, want 1; findings=%v", got, findings)
	}
	if got := countFindingM8(findings, "F-CI-ENV-002"); got != 1 {
		t.Fatalf("F-CI-ENV-002 count = %d, want 1; findings=%v", got, findings)
	}
	for _, f := range findings {
		if f.ID == "F-CI-ENV-001" && len(f.Evidence) != 2 {
			t.Fatalf("F-CI-ENV-001 evidence count = %d, want 2", len(f.Evidence))
		}
		if f.ID == "F-CI-ENV-002" && len(f.Evidence) != 2 {
			t.Fatalf("F-CI-ENV-002 evidence count = %d, want 2", len(f.Evidence))
		}
	}
}

func TestM8Engine_ConfigIgnoresSelectedCIEnvParityKeys(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__CI_ONLY_ALLOWED", Value: "value"},
				{Source: "ci_env__job__test__CI_ONLY_MISSING", Value: "value"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: LOCAL_ONLY_ALLOWED, LOCAL_ONLY_MISSING"},
			}},
			{Name: "config", Evidence: []schema.Evidence{
				{Source: "devdiag_ci_env_ignore_missing_local", Value: "CI_ONLY_ALLOWED"},
				{Source: "devdiag_ci_env_ignore_missing_ci", Value: "LOCAL_ONLY_ALLOWED"},
			}},
		},
	}

	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.ID == "F-CI-ENV-001" {
			assertFindingEvidenceAbsentM8(t, f, "CI_ONLY_ALLOWED")
			assertFindingEvidenceValueM8(t, f, "CI_ONLY_MISSING")
		}
		if f.ID == "F-CI-ENV-002" {
			assertFindingEvidenceAbsentM8(t, f, "LOCAL_ONLY_ALLOWED")
			assertFindingEvidenceValueM8(t, f, "LOCAL_ONLY_MISSING")
		}
	}
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

func TestM8Engine_ServiceNameMismatchDespiteMatchingHostPort(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__test__postgres__image", Value: "postgres:15"},
				{Source: "ci_service__test__postgres__host_port", Value: "5432"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_host_port", Value: "5432"},
				{Source: "compose_service__redis__image", Value: "redis:7"},
				{Source: "compose_service__redis__host_port", Value: "5432"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-SERVICE-001")
}

func TestM8Engine_ServiceImageMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__test__postgres__image", Value: "postgres:15"},
				{Source: "ci_service__test__postgres__host_port", Value: "5432"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_host_port", Value: "5432"},
				{Source: "compose_service__postgres__image", Value: "postgres:14"},
				{Source: "compose_service__postgres__host_port", Value: "5432"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-SERVICE-001")
}

func TestM8Engine_ServiceMatchIgnoresCIJobSegment(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__test__postgres__image", Value: "postgres:15"},
				{Source: "ci_service__test__postgres__host_port", Value: "5432"},
				{Source: "ci_service__test__postgres__container_port", Value: "5432"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_service__postgres__image", Value: "postgres:15"},
				{Source: "compose_service__postgres__host_port", Value: "5432"},
				{Source: "compose_service__postgres__container_port", Value: "5432"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-SERVICE-001")
	assertNoFindingM8(t, findings, "F-CI-SERVICE-002")
}

func TestM8Engine_SuppressesComposeServiceMissingWhenCIDefinesNoServices(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "npm test"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_service__redis__image", Value: "redis:7"},
				{Source: "compose_service__redis__host_port", Value: "6379"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-SERVICE-002")
}

func TestM8Engine_ComposeServiceMissingInCIWhenCIHasServices(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__test__postgres__image", Value: "postgres:15"},
				{Source: "ci_service__test__postgres__host_port", Value: "5432"},
			}},
			{Name: "compose", Evidence: []schema.Evidence{
				{Source: "compose_service__postgres__image", Value: "postgres:15"},
				{Source: "compose_service__postgres__host_port", Value: "5432"},
				{Source: "compose_service__redis__image", Value: "redis:7"},
				{Source: "compose_service__redis__host_port", Value: "6379"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-SERVICE-001")
	assertFindingM8(t, findings, "F-CI-SERVICE-002")
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

func TestM8Engine_ContainerImageDetectsDifferentRegistryWithSameSuffix(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_container__test__image", Value: "ghcr.io/acme/node:20"},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "devcontainer_image", Value: "node:20"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-CONTAINER-001")
}

func TestM8Engine_ContainerImageNormalizesDockerHubLibrary(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_container__test__image", Value: "docker.io/library/node:20"},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "devcontainer_image", Value: "node:20"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-CONTAINER-001")
}

func TestM8Engine_PackageManagerMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "npm test"},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "repo_package_manager", Value: "pnpm@9.0.0"},
				{Source: "repo_command__package_json__test", Value: "pnpm test"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-PACKAGE-002")
	assertNoFindingM8(t, findings, "F-CI-COMMAND-001")
}

func TestM8Engine_CIRunCommandMissingLocalCommand(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "pnpm e2e"},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "repo_package_manager", Value: "pnpm@9.0.0"},
				{Source: "repo_command__package_json__test", Value: "pnpm test"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-COMMAND-001")
}

func TestM8Engine_CIRunCommandTitleSummarizesMultilineScripts(t *testing.T) {
	e := NewM8Engine()
	longScript := "docker system prune -af\nsudo rm -rf /usr/share/dotnet\nnpm ci\nnpm run build\nnpm test"
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__deploy__0", Value: longScript},
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "repo_command__package_json__test", Value: "npm test"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.ID == "F-CI-COMMAND-001" {
			if strings.Contains(f.Title, "\n") {
				t.Fatalf("finding title contains a newline: %q", f.Title)
			}
			if len(f.Title) > 130 {
				t.Fatalf("finding title too long: %d %q", len(f.Title), f.Title)
			}
			if f.Evidence[1].Value != longScript {
				t.Fatalf("full command evidence changed: %q", f.Evidence[1].Value)
			}
			return
		}
	}
	t.Fatalf("expected F-CI-COMMAND-001, got: %v", findings)
}

func TestM8Engine_CIUndocumentedCommandsGrouped(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_run__test__0", Value: "pnpm e2e"},
				{Source: "ci_run__test__1", Value: "pnpm integration"},
				{Source: "ci_run__test__2", Value: "pnpm e2e"}, // duplicate, should be deduped
			}},
			{Name: "repo", Evidence: []schema.Evidence{
				{Source: "repo_package_manager", Value: "pnpm@9.0.0"},
				{Source: "repo_command__package_json__test", Value: "pnpm test"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	var cmdFinding *schema.Finding
	for i := range findings {
		if findings[i].ID == "F-CI-COMMAND-001" {
			cmdFinding = &findings[i]
		}
	}
	if cmdFinding == nil {
		t.Fatal("expected F-CI-COMMAND-001 finding")
	}

	// Should have title: "CI has 2 undocumented commands"
	if cmdFinding.Title != "CI has 2 undocumented commands" {
		t.Errorf("unexpected title: %q", cmdFinding.Title)
	}

	// Evidence count should be 3 (stable count + 2 unique commands)
	if len(cmdFinding.Evidence) != 3 {
		t.Fatalf("expected 3 evidence items, got %d: %v", len(cmdFinding.Evidence), cmdFinding.Evidence)
	}

	if cmdFinding.Evidence[0].Source != "ci_undocumented_command_count" || cmdFinding.Evidence[0].Value != "2" {
		t.Errorf("unexpected stable evidence: %v", cmdFinding.Evidence[0])
	}
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

func TestM8Engine_JobEnvKeyExtractionWithDoubleUnderscoreJob(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__build__prod__API_KEY", Value: "${{ secrets.API_KEY }}"},
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
		if f.ID == "F-CI-ENV-001" && !strings.Contains(f.Title, "API_KEY") {
			t.Errorf("expected finding title to reference API_KEY, got: %s", f.Title)
		}
	}
}

func TestM8Engine_DecodesEscapedEnvKeySegments(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__job__test__API%5F%5FKEY", Value: "${{ secrets.API__KEY }}"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: API__KEY"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-ENV-001")
	assertNoFindingM8(t, findings, "F-CI-ENV-002")
}

func TestM8Engine_SetupInfoParsesDoubleUnderscoreJob(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__build__prod__0__setup_node__node_version", Value: "20"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: ".nvmrc", Value: "node 20"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-PACKAGE-001")
	assertNoFindingM8(t, findings, "F-CI-RUNTIME-001")
}

func TestM8Engine_ServicePortParsesDoubleUnderscoreJobAndEscapedService(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_service__build__prod__postgres%5F%5Fprimary__host_port", Value: "5432"},
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
	for _, f := range findings {
		if f.ID == "F-CI-SERVICE-001" && !strings.Contains(f.Title, "postgres__primary") {
			t.Errorf("expected finding title to reference decoded service name, got: %s", f.Title)
		}
	}
}

func TestM8Engine_PackageJSONNodeRangeCompatibleWithCI(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__0__setup_node__node_version", Value: "22"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: "package.json", Value: `engines: "node": ">=20 <23"`},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-RUNTIME-001")
}

func TestM8Engine_NestedPackageJSONNodeRangeCompatibleWithCI(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__docs__0__setup_node__node_version", Value: "24"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: "docs-site/package.json", Value: `engines: "node": ">=24"`},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-PACKAGE-001")
	assertNoFindingM8(t, findings, "F-CI-RUNTIME-001")
}

func TestM8Engine_GroupsMissingRuntimePinBySetupAction(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__0__setup_node__node_version", Value: "22"},
				{Source: "ci_setup__build__0__setup_node__node_version", Value: "22"},
				{Source: "ci_setup__docs__0__setup_node__node_version", Value: "22"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got := countFindingM8(findings, "F-CI-PACKAGE-001"); got != 1 {
		t.Fatalf("F-CI-PACKAGE-001 count = %d, want 1; findings=%v", got, findings)
	}
}

func TestM8Engine_GroupsMissingRuntimePinAcrossMatrixVersions(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__matrix_0__setup_python__python_version", Value: "3.10"},
				{Source: "ci_setup__test__matrix_1__setup_python__python_version", Value: "3.11"},
				{Source: "ci_setup__lint__0__setup_python__python_version", Value: "3.11"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got := countFindingM8(findings, "F-CI-PACKAGE-001"); got != 1 {
		t.Fatalf("F-CI-PACKAGE-001 count = %d, want 1; findings=%v", got, findings)
	}
	for _, f := range findings {
		if f.ID != "F-CI-PACKAGE-001" {
			continue
		}
		if !strings.Contains(f.Symptom, "3.10, 3.11") {
			t.Fatalf("finding symptom should summarize matrix values, got %q", f.Symptom)
		}
		if len(f.Evidence) != 3 {
			t.Fatalf("finding should keep all setup evidence, got %d: %v", len(f.Evidence), f.Evidence)
		}
		return
	}
	t.Fatal("missing F-CI-PACKAGE-001")
}

func TestM8Engine_IgnoresOpaqueMatrixExpressionWhenConcreteMatrixValueExists(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__0__setup_node__node_version", Value: "${{ matrix.node }}"},
				{Source: "ci_setup__test__matrix_0__setup_node__node_version", Value: "20"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: ".nvmrc", Value: "node 20"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFindingM8(t, findings, "F-CI-RUNTIME-001")
}

func TestM8Engine_DotnetRuntimeMismatch(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_setup__test__0__setup_dotnet__dotnet_version", Value: "9.0.x"},
			}},
			{Name: "runtime", Evidence: []schema.Evidence{
				{Source: "global.json", Value: "dotnet 8.0.204"},
			}},
		},
	}
	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingM8(t, findings, "F-CI-RUNTIME-001")
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

func TestCheckCI_ConfigIgnoresDeploymentSecrets(t *testing.T) {
	e := NewM8Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{Name: "config", Evidence: []schema.Evidence{
				{Source: "devdiag_ci_env_deployment_only", Value: "CONFIRM_DEPLOY"},
				{Source: "devdiag_ci_env_local_required", Value: "REQUIRED_LOCAL_VAR"},
				{Source: "devdiag_ci_env_ci_only", Value: "DOTNET_VERSION"},
			}},
			{Name: "ci", Evidence: []schema.Evidence{
				{Source: "ci_env__workflow__CONFIRM_DEPLOY", Value: "deploy-v1"},
				{Source: "ci_env__workflow__OCI_SSH_PRIVATE_KEY", Value: "${{ secrets.OCI_SSH_PRIVATE_KEY }}"},
				{Source: "ci_env__workflow__REQUIRED_LOCAL_VAR", Value: "some-val"},
				{Source: "ci_env__workflow__DOTNET_VERSION", Value: "8.0"},
				{Source: "ci_env__workflow__NORMAL_CI_VAR", Value: "normal"},
			}},
			{Name: "env", Evidence: []schema.Evidence{
				{Source: ".env", Value: "keys: OTHER_LOCAL_VAR"},
			}},
		},
	}

	findings, err := e.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	var hasParity001, hasDeployInfo bool
	for _, f := range findings {
		if f.ID == "F-CI-ENV-001" {
			hasParity001 = true
			if strings.Contains(f.Title, "CONFIRM_DEPLOY") {
				t.Error("CONFIRM_DEPLOY should not trigger F-CI-ENV-001")
			}
			if strings.Contains(f.Title, "OCI_SSH_PRIVATE_KEY") {
				t.Error("OCI_SSH_PRIVATE_KEY should not trigger F-CI-ENV-001")
			}
			if strings.Contains(f.Title, "DOTNET_VERSION") {
				t.Error("DOTNET_VERSION should not trigger F-CI-ENV-001")
			}
			if !strings.Contains(f.Title, "REQUIRED_LOCAL_VAR") {
				t.Error("expected REQUIRED_LOCAL_VAR in F-CI-ENV-001")
			}
			if !strings.Contains(f.Title, "NORMAL_CI_VAR") {
				t.Error("expected NORMAL_CI_VAR in F-CI-ENV-001")
			}
		}
		if f.ID == "F-CI-ENV-DEPLOY-INFO" {
			hasDeployInfo = true
			if f.Severity != schema.SeverityInfo {
				t.Errorf("expected SeverityInfo for F-CI-ENV-DEPLOY-INFO, got %s", f.Severity)
			}
			if !strings.Contains(f.Title, "CONFIRM_DEPLOY") {
				t.Error("expected CONFIRM_DEPLOY in F-CI-ENV-DEPLOY-INFO")
			}
			if !strings.Contains(f.Title, "OCI_SSH_PRIVATE_KEY") {
				t.Error("expected OCI_SSH_PRIVATE_KEY in F-CI-ENV-DEPLOY-INFO")
			}
		}
	}

	if !hasParity001 {
		t.Error("expected F-CI-ENV-001 finding")
	}
	if !hasDeployInfo {
		t.Error("expected F-CI-ENV-DEPLOY-INFO finding")
	}
}
