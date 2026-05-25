package configschema

import (
	"strings"
	"testing"
)

func TestValidateYAMLAcceptsDevDiagConfig(t *testing.T) {
	result := ValidateYAML([]byte(`schema_version: "1"
ci:
  env:
    ignore_missing_local: [API_KEY]
policy:
  fail_severity: medium
`))
	if !result.Valid {
		t.Fatalf("ValidateYAML invalid: %+v", result.Errors)
	}
	if result.Config.Policy.FailSeverity != "medium" {
		t.Fatalf("fail_severity = %q, want medium", result.Config.Policy.FailSeverity)
	}
}

func TestValidateYAMLRejectsInvalidFailSeverity(t *testing.T) {
	result := ValidateYAML([]byte(`policy:
  fail_severity: urgent
`))
	if result.Valid {
		t.Fatalf("ValidateYAML valid, want invalid")
	}
	if !containsConfigError(result.Errors, "fail_severity") {
		t.Fatalf("errors = %+v, want fail_severity error", result.Errors)
	}
}

func TestValidateYAMLRejectsUnknownFields(t *testing.T) {
	result := ValidateYAML([]byte(`policy:
  fail_severity: medium
shell: rm -rf /
`))
	if result.Valid {
		t.Fatalf("ValidateYAML valid, want invalid")
	}
	if !containsConfigError(result.Errors, "shell") {
		t.Fatalf("errors = %+v, want unknown shell field error", result.Errors)
	}
}

func containsConfigError(errors []string, want string) bool {
	for _, err := range errors {
		if strings.Contains(err, want) {
			return true
		}
	}
	return false
}
