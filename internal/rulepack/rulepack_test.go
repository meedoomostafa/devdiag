package rulepack

import "testing"

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
		if err == want {
			return true
		}
	}
	return false
}
