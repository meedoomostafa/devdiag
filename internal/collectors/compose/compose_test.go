package compose

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_ExtractsEnvRefs(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    image: myapp:${TAG:-latest}
    environment:
      DATABASE_URL: ${DATABASE_URL:?required}
      API_KEY: ${API_KEY}
    ports:
      - "${PORT:-3000}:3000"
    command: echo $$HOME && run ${MODE}
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %s, want ok", res.Status)
	}

	var vars []string
	for _, ev := range res.Evidence {
		vars = append(vars, ev.Value)
	}

	// Should find TAG, DATABASE_URL, API_KEY, PORT, MODE
	// Should NOT find escaped $$HOME
	wantVars := map[string]bool{
		"TAG":          false,
		"DATABASE_URL": false,
		"API_KEY":      false,
		"PORT":         false,
		"MODE":         false,
	}
	for _, v := range vars {
		for w := range wantVars {
			if contains(v, w) {
				wantVars[w] = true
			}
		}
	}

	for v, found := range wantVars {
		if !found {
			t.Errorf("expected to find variable %q in evidence, got: %v", v, vars)
		}
	}

	// Make sure $$HOME is not present
	for _, v := range vars {
		if contains(v, "HOME") {
			t.Errorf("did not expect escaped HOME variable in evidence, got: %q", v)
		}
	}
}

func TestCollector_NoComposeFile(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(res.Evidence) != 0 {
		t.Errorf("expected no evidence without compose file, got %d", len(res.Evidence))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCollector_DefaultValueNotMissing(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    environment:
      PORT: ${PORT:-3000}
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	// PORT with default should still be reported as evidence (rule layer decides if it's a finding)
	var found bool
	for _, ev := range res.Evidence {
		if contains(ev.Value, "PORT") {
			found = true
		}
	}
	if !found {
		t.Error("expected PORT evidence")
	}
}

func TestCollector_RequiredValue(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    environment:
      DATABASE_URL: ${DATABASE_URL:?required}
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var found bool
	for _, ev := range res.Evidence {
		if contains(ev.Value, "DATABASE_URL") && contains(ev.Value, "?required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DATABASE_URL required evidence, got: %v", res.Evidence)
	}
}

func TestCollector_EscapedDollarIgnored(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    command: echo $$HOME
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	refs, err := extractEnvRefs(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractEnvRefs error: %v", err)
	}
	for _, ref := range refs {
		if ref.Var == "HOME" {
			t.Errorf("escaped $$HOME should not be extracted, got: %v", ref)
		}
	}
}

func TestCollector_PortMappings(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  api:
    ports:
      - "5432:5432"
      - "127.0.0.1:8000:8000"
      - "127.0.0.1:9000"
      - "5432"
      - "${PORT:-3000}:3000"
      - "${PORT_MISSING}:4000"
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	ports, err := extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}

	want := []string{"5432", "8000", "9000", "3000"}
	if len(ports) != len(want) {
		t.Fatalf("expected %v, got %v", want, ports)
	}
	for i, w := range want {
		if ports[i] != w {
			t.Errorf("port[%d] = %q, want %q", i, ports[i], w)
		}
	}
}

func TestCollector_ServiceImageAndPorts(t *testing.T) {
	dir := t.TempDir()
	yaml := `services:
  postgres:
    image: postgres:15
    ports:
      - "5432:5432/tcp"
  redis:
    image: redis:7
    ports:
      - "127.0.0.1:6379:6379"
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	checks := map[string]string{
		"compose_service__postgres__image":          "postgres:15",
		"compose_service__postgres__host_port":      "5432",
		"compose_service__postgres__container_port": "5432",
		"compose_service__redis__image":             "redis:7",
		"compose_service__redis__host_port":         "6379",
		"compose_service__redis__container_port":    "6379",
	}
	for source, value := range checks {
		var found bool
		for _, ev := range res.Evidence {
			if ev.Source == source && ev.Value == value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected evidence %s=%s in %v", source, value, res.Evidence)
		}
	}
}

func TestCollector_LineNumbersPreserved(t *testing.T) {
	dir := t.TempDir()
	yaml := "services:\n  api:\n    environment:\n      API_KEY: ${API_KEY}\n"
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yaml), 0644)

	refs, err := extractEnvRefs(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractEnvRefs error: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("expected refs")
	}
	if refs[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestCollector_InterpolatedPortsWithReplacement(t *testing.T) {
	// Unset ALT_PORT
	t.Setenv("ALT_PORT", "") // empty
	os.Unsetenv("ALT_PORT")  // truly unset

	// Case 1: ALT_PORT is unset
	dir := t.TempDir()
	yamlContent := `services:
  api:
    ports:
      - "${ALT_PORT:+18080}:80"
      - "${ALT_PORT+18081}:80"
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yamlContent), 0644)
	ports, err := extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}
	if len(ports) != 0 {
		t.Fatalf("expected 0 ports when ALT_PORT is unset, got: %v", ports)
	}

	// Case 2: ALT_PORT is set to empty string
	t.Setenv("ALT_PORT", "")
	ports, err = extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}
	// With ALT_PORT="", ${ALT_PORT:+18080} should not resolve, but ${ALT_PORT+18081} should resolve (since it's set).
	if len(ports) != 1 || ports[0] != "18081" {
		t.Fatalf("expected [18081] when ALT_PORT is empty, got: %v", ports)
	}

	// Case 3: ALT_PORT is set to a non-empty string
	t.Setenv("ALT_PORT", "something")
	ports, err = extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}
	// Both should resolve
	if len(ports) != 2 || ports[0] != "18080" || ports[1] != "18081" {
		t.Fatalf("expected [18080, 18081] when ALT_PORT is set, got: %v", ports)
	}
}

func TestCollector_InterpolatedPortsWithDefaultsPreferEnvValue(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `services:
  api:
    ports:
      - "${APP_PORT:-3000}:80"
      - "${APP_PORT2-3001}:81"
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yamlContent), 0644)

	t.Setenv("APP_PORT", "7777")
	t.Setenv("APP_PORT2", "8888")
	ports, err := extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}
	if len(ports) != 2 || ports[0] != "7777" || ports[1] != "8888" {
		t.Fatalf("expected env ports [7777, 8888], got: %v", ports)
	}

	t.Setenv("APP_PORT", "")
	t.Setenv("APP_PORT2", "")
	ports, err = extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}
	if len(ports) != 1 || ports[0] != "3000" {
		t.Fatalf("expected empty-aware ports [3000], got: %v", ports)
	}
}

func TestCollector_InterpolatedPortsWithDirectEnvValue(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `services:
  api:
    ports:
      - "${DIRECT_PORT}:80"
      - "$SIMPLE_PORT:81"
      - "${MISSING_DIRECT_PORT}:82"
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(yamlContent), 0644)

	t.Setenv("DIRECT_PORT", "7000")
	t.Setenv("SIMPLE_PORT", "7001")
	ports, err := extractPortMappings(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("extractPortMappings error: %v", err)
	}
	if len(ports) != 2 || ports[0] != "7000" || ports[1] != "7001" {
		t.Fatalf("expected direct env ports [7000, 7001], got: %v", ports)
	}
}
