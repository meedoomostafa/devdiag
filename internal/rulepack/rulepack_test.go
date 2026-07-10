package rulepack

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestBuiltInPacksListMilestoneRuleGroups(t *testing.T) {
	packs := BuiltInPacks()
	for _, want := range []string{"core", "containers", "gpu-ml", "ci", "agent-safety"} {
		if !hasPack(packs, want) {
			t.Fatalf("BuiltInPacks missing %q: %+v", want, packs)
		}
	}
}

func TestValidatePackAcceptsMinimalTeamPack(t *testing.T) {
	pack, result := Validate([]byte(`id: team-baseline
version: 2026.05
engine: go
rules:
  - id: F-CI-ENV-001
    severity: medium
`))
	if !result.Valid {
		t.Fatalf("Validate() invalid: %+v", result.Errors)
	}
	if pack.ID != "team-baseline" || len(pack.Rules) != 1 {
		t.Fatalf("pack = %+v", pack)
	}
}

func TestValidatePackAcceptsRegoPolicyPack(t *testing.T) {
	pack, result := Validate([]byte(`schema_version: "1"
id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files:
  - policy.rego
rules:
  - id: F-TEAM-001
    severity: medium
`))
	if !result.Valid {
		t.Fatalf("Validate() invalid: %+v", result.Errors)
	}
	if pack.Engine != "rego" || pack.Entrypoint == "" || len(pack.PolicyFiles) != 1 {
		t.Fatalf("pack rego metadata not decoded: %+v", pack)
	}
}

func TestValidatePackRejectsRegoWithoutEntrypoint(t *testing.T) {
	_, result := Validate([]byte(`id: team-rego
version: "0.1"
engine: rego
policy_files: [policy.rego]
rules:
  - id: F-TEAM-001
    severity: medium
`))
	if result.Valid {
		t.Fatalf("Validate() valid, want invalid")
	}
	if !hasError(result.Errors, "rego rule packs require entrypoint") {
		t.Fatalf("Validate() errors = %+v, want entrypoint error", result.Errors)
	}
}

func TestValidatePackRejectsUnsupportedEngineAndUnsafePolicyPath(t *testing.T) {
	_, result := Validate([]byte(`id: team-rego
version: "0.1"
engine: shell
entrypoint: data.devdiag.findings
policy_files: [../policy.rego]
rules:
  - id: F-TEAM-001
    severity: medium
`))
	if result.Valid {
		t.Fatalf("Validate() valid, want invalid")
	}
	if !hasError(result.Errors, "unsupported") || !hasError(result.Errors, "unsafe") {
		t.Fatalf("Validate() errors = %+v, want unsupported and unsafe errors", result.Errors)
	}
}

func TestValidatePackRejectsMutationAndShellExecutionMetadata(t *testing.T) {
	_, result := Validate([]byte(`id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files: [policy.rego]
command: rm -rf /
mutates: true
rules:
  - id: F-TEAM-001
    severity: medium
`))
	if result.Valid {
		t.Fatalf("Validate() valid, want invalid")
	}
	if !hasError(result.Errors, "command") || !hasError(result.Errors, "mutates") {
		t.Fatalf("Validate() errors = %+v, want command and mutates field errors", result.Errors)
	}
}

func TestValidatePackRejectsMissingRuleIDAndUnknownSeverity(t *testing.T) {
	_, result := Validate([]byte(`id: team-baseline
version: 2026.05
rules:
  - severity: urgent
`))
	if result.Valid {
		t.Fatalf("Validate() valid, want invalid")
	}
	if len(result.Errors) < 2 {
		t.Fatalf("Validate() errors = %+v, want missing rule id and bad severity", result.Errors)
	}
}

func TestValidatePackRejectsDuplicateRuleIDs(t *testing.T) {
	_, result := Validate([]byte(`id: team-baseline
version: 2026.05
rules:
  - id: F-CI-ENV-001
    severity: medium
  - id: F-CI-ENV-001
    severity: high
`))
	if result.Valid {
		t.Fatalf("Validate() valid, want invalid")
	}
	if !hasError(result.Errors, `rules[1].id "F-CI-ENV-001" is duplicated`) {
		t.Fatalf("Validate() errors = %+v, want duplicate rule id", result.Errors)
	}
}

func TestEvaluateRegoFileReturnsFindingCandidates(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(packPath, []byte(`id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files: [policy.rego]
rules:
  - id: F-TEAM-001
    severity: high
`), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`package devdiag

findings contains {
  "id": "F-TEAM-001",
  "title": "Team policy matched repo collector",
  "severity": "high",
  "confidence": 0.9,
  "symptom": "Repo collector is present"
} if {
  some c in input.collectors
  c.collector == "repo"
}
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	snapshot := graph.NormalizedSnapshot{Collectors: []schema.CollectorResult{{Name: "repo", Status: schema.CollectorOK}}}

	result := EvaluateRegoFile(context.Background(), packPath, snapshot)
	if !result.Valid {
		t.Fatalf("EvaluateRegoFile invalid: %+v", result.Errors)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "F-TEAM-001" {
		t.Fatalf("findings = %+v, want F-TEAM-001", result.Findings)
	}
}

func TestEvaluateRegoFileRejectsNetworkBuiltin(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(packPath, []byte(`id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files: [policy.rego]
rules:
  - id: F-TEAM-001
    severity: high
`), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`package devdiag
findings := [http.send({"method": "get", "url": "https://example.com"})]
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	result := EvaluateRegoFile(context.Background(), packPath, graph.NormalizedSnapshot{})
	if result.Valid {
		t.Fatalf("EvaluateRegoFile valid, want invalid")
	}
	if !hasError(result.Errors, "unsupported token") {
		t.Fatalf("errors = %+v, want unsupported token", result.Errors)
	}
}

func TestEvaluateRegoFileRejectsMalformedFindingIDs(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(packPath, []byte(`id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files: [policy.rego]
rules:
  - id: F-TEAM-001
    severity: high
`), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`package devdiag
findings := [{
  "id": "not a finding id; rm -rf",
  "title": "spoofed",
  "severity": "high"
}]
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	result := EvaluateRegoFile(context.Background(), packPath, graph.NormalizedSnapshot{})
	if result.Valid {
		t.Fatalf("EvaluateRegoFile valid, want invalid for malformed finding id")
	}
	if !hasError(result.Errors, "finding id") {
		t.Fatalf("errors = %+v, want finding id validation error", result.Errors)
	}
}

func TestEvaluateRegoFileClampsConfidence(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(packPath, []byte(`id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files: [policy.rego]
rules:
  - id: F-TEAM-001
    severity: high
`), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`package devdiag
findings := [{
  "id": "F-TEAM-001",
  "title": "confidence out of range",
  "severity": "high",
  "confidence": 42.5
}]
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	result := EvaluateRegoFile(context.Background(), packPath, graph.NormalizedSnapshot{})
	if !result.Valid {
		t.Fatalf("EvaluateRegoFile invalid: %+v", result.Errors)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	if c := result.Findings[0].Confidence; c < 0 || c > 1 {
		t.Fatalf("confidence = %v, want clamped to [0,1]", c)
	}
}

func TestEvaluateRegoFileTimesOutOnPathologicalPolicy(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(packPath, []byte(`id: team-rego
version: "0.1"
engine: rego
entrypoint: data.devdiag.findings
policy_files: [policy.rego]
rules:
  - id: F-TEAM-001
    severity: high
`), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	// Cross-product comprehension over large ranges: effectively unbounded work.
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`package devdiag
findings := [x |
  some a in numbers.range(1, 100000)
  some b in numbers.range(1, 100000)
  x := {"id": sprintf("F-%d-%d", [a, b]), "title": "t", "severity": "high"}
]
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	prev := regoEvalTimeout
	regoEvalTimeout = 100 * time.Millisecond
	defer func() { regoEvalTimeout = prev }()

	start := time.Now()
	result := EvaluateRegoFile(context.Background(), packPath, graph.NormalizedSnapshot{})
	elapsed := time.Since(start)

	if result.Valid {
		t.Fatalf("EvaluateRegoFile valid, want invalid due to timeout")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("evaluation ran %v, expected timeout near 100ms", elapsed)
	}
}

func hasPack(packs []Pack, id string) bool {
	for _, pack := range packs {
		if pack.ID == id {
			return true
		}
	}
	return false
}

func hasError(errors []string, want string) bool {
	for _, err := range errors {
		if err == want || strings.Contains(err, want) {
			return true
		}
	}
	return false
}
