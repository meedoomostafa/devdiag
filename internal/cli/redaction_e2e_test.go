package cli

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Canary values planted in the fixture. Any appearance in a default-redaction
// sink is a redaction-contract regression.
const (
	canaryEnvSecret     = "CANARYAWSKEYabcdef1234567890ABCDEF12345678"
	canaryURLSecret     = "CANARY_URL_SECRET_XYZ123"
	canaryComposeSecret = "CANARYCOMPOSEDEFAULT999"
)

var canaries = []string{canaryEnvSecret, canaryURLSecret, canaryComposeSecret}

// writeCanaryFixture creates a repo whose CI workflow and compose file carry
// secret material through three distinct leak channels: a bare job env value,
// URL-embedded credentials, and a compose interpolation default.
func writeCanaryFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: fixture
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      AWS_SECRET_ACCESS_KEY: ` + canaryEnvSecret + `
      SERVICE_URL: https://devdiag:` + canaryURLSecret + `@example.invalid/resource
    steps:
      - run: npm test
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  app:
    image: node:20
    environment:
      - API_TOKEN=${API_TOKEN:-` + canaryComposeSecret + `}
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nvmrc"), []byte("18\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertNoCanary(t *testing.T, sink, content string) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(content, c) {
			idx := strings.Index(content, c)
			lo := idx - 80
			if lo < 0 {
				lo = 0
			}
			hi := idx + len(c) + 40
			if hi > len(content) {
				hi = len(content)
			}
			t.Errorf("canary %q leaked into %s: ...%s...", c, sink, content[lo:hi])
		}
	}
}

func TestRedactionE2E_OffModePositiveControl(t *testing.T) {
	// Positive control: prove every canary actually reaches the collectors.
	// Without this, the absence checks below could pass vacuously when
	// collection silently fails.
	dir := writeCanaryFixture(t)
	stdout, stderr, _ := runBinaryInDir(dir, "scan", ".", "--format", "json", "--redact", "off", "--view", "all", "--include-hidden")
	combined := stdout + stderr
	for _, c := range canaries {
		if !strings.Contains(combined, c) {
			t.Fatalf("positive control failed: canary %q never reached collector output; fixture or collector changed. stderr: %s", c, stderr)
		}
	}
}

func TestRedactionE2E_StdoutAllFormats(t *testing.T) {
	dir := writeCanaryFixture(t)
	for _, format := range []string{"human", "json", "ndjson", "markdown", "github"} {
		for _, level := range []string{"default", "strict"} {
			t.Run(format+"/"+level, func(t *testing.T) {
				stdout, stderr, code := runBinaryInDir(dir, "scan", ".", "--format", format, "--redact", level, "--view", "all", "--include-hidden", "--verbose")
				if code > 1 {
					t.Fatalf("scan exited %d (want 0 or 1); stderr: %s", code, stderr)
				}
				if strings.TrimSpace(stdout) == "" {
					t.Fatalf("scan produced empty stdout for %s/%s; canary checks would be vacuous", format, level)
				}
				assertNoCanary(t, "scan stdout ("+format+"/"+level+")", stdout)
				assertNoCanary(t, "scan stderr ("+format+"/"+level+")", stderr)
			})
		}
	}
}

func TestRedactionE2E_SavedReport(t *testing.T) {
	dir := writeCanaryFixture(t)
	_, stderr, code := runBinaryInDir(dir, "scan", ".", "--save-report", "--format", "json")
	if code > 1 {
		t.Fatalf("scan exited %d (want 0 or 1); stderr: %s", code, stderr)
	}
	reports, err := filepath.Glob(filepath.Join(dir, ".devdiag", "runs", "*", "report.json"))
	if err != nil || len(reports) == 0 {
		t.Fatalf("no saved report found: %v (stderr: %s)", err, stderr)
	}
	for _, rep := range reports {
		data, err := os.ReadFile(rep)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Fatalf("saved report %s is empty; canary check would be vacuous", rep)
		}
		assertNoCanary(t, "saved report "+rep, string(data))
	}
}

func TestRedactionE2E_CapsuleMembers(t *testing.T) {
	dir := writeCanaryFixture(t)
	if _, stderr, code := runBinaryInDir(dir, "scan", ".", "--save-report", "--format", "json"); code > 1 {
		t.Fatalf("scan failed: exit %d, stderr: %s", code, stderr)
	}
	if _, stderr, code := runBinaryInDir(dir, "capsule", "create", "."); code != 0 {
		t.Fatalf("capsule create failed: exit %d, stderr: %s", code, stderr)
	}
	capsules, err := filepath.Glob(filepath.Join(dir, "support-*.devdiag.tgz"))
	if err != nil || len(capsules) != 1 {
		t.Fatalf("expected one capsule, got %v (%v)", capsules, err)
	}
	f, err := os.Open(capsules[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	members := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		members++
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		assertNoCanary(t, "capsule member "+hdr.Name, string(data))
	}
	if members == 0 {
		t.Fatal("capsule contained no regular files")
	}
}
