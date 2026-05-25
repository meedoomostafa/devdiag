package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollectorReadsCIEnvIgnoreProfile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".devdiag.yml")
	data := []byte(`ci:
  env:
    ignore_missing_local:
      - CI_ONLY_ALLOWED
      - "CI_SECRET"
    ignore_missing_ci:
      - LOCAL_ONLY_ALLOWED
`)
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	res, err := (&Collector{Root: dir}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %s, want ok; notes=%v", res.Status, res.Notes)
	}
	assertConfigEvidence(t, res.Evidence, "devdiag_config_path", ".devdiag.yml")
	assertConfigEvidence(t, res.Evidence, "devdiag_ci_env_ignore_missing_local", "CI_ONLY_ALLOWED")
	assertConfigEvidence(t, res.Evidence, "devdiag_ci_env_ignore_missing_local", "CI_SECRET")
	assertConfigEvidence(t, res.Evidence, "devdiag_ci_env_ignore_missing_ci", "LOCAL_ONLY_ALLOWED")
}

func TestCollectorPrefersShareableDevDiagYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".devdiag.yml"), []byte(`ci:
  env:
    ignore_missing_local:
      - LEGACY_ONLY
`), 0o644); err != nil {
		t.Fatalf("write legacy config fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devdiag.yaml"), []byte(`ci:
  env:
    ignore_missing_local:
      - TEAM_BASELINE
policy:
  fail_severity: medium
`), 0o644); err != nil {
		t.Fatalf("write team config fixture: %v", err)
	}

	res, err := (&Collector{Root: dir}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	assertConfigEvidence(t, res.Evidence, "devdiag_config_path", "devdiag.yaml")
	assertConfigEvidence(t, res.Evidence, "devdiag_ci_env_ignore_missing_local", "TEAM_BASELINE")
	assertConfigEvidence(t, res.Evidence, "devdiag_policy_fail_severity", "medium")
	for _, ev := range res.Evidence {
		if ev.Value == "LEGACY_ONLY" {
			t.Fatalf("legacy config should not win over devdiag.yaml: %v", res.Evidence)
		}
	}
}

func TestCollectorMissingConfigIsOK(t *testing.T) {
	res, err := (&Collector{Root: t.TempDir()}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %s, want ok", res.Status)
	}
	if len(res.Evidence) != 0 {
		t.Fatalf("expected no evidence for missing config, got %v", res.Evidence)
	}
}

func TestCollectorMalformedConfigIsPartial(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".devdiag.yml"), []byte("ci: ["), 0o644); err != nil {
		t.Fatalf("write malformed config fixture: %v", err)
	}

	res, err := (&Collector{Root: dir}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorPartial {
		t.Fatalf("status = %s, want partial", res.Status)
	}
	if len(res.Notes) == 0 {
		t.Fatal("expected parse error note for malformed config")
	}
}

func TestCollectorInvalidFailSeverityIsPartial(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "devdiag.yaml"), []byte("policy:\n  fail_severity: urgent\n"), 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	res, err := (&Collector{Root: dir}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorPartial {
		t.Fatalf("status = %s, want partial", res.Status)
	}
	assertConfigEvidence(t, res.Evidence, "devdiag_config_path", "devdiag.yaml")
	if len(res.Notes) == 0 {
		t.Fatal("expected invalid fail severity note")
	}
}

func assertConfigEvidence(t *testing.T, evidence []schema.Evidence, source, value string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			return
		}
	}
	t.Fatalf("missing evidence %s=%s in %v", source, value, evidence)
}
