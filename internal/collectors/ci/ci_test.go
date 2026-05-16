package ci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_ExtractsRunCommands(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: npm install
      - name: Test
        run: npm test
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %s, want ok", res.Status)
	}

	var hasInstall, hasTest bool
	for _, ev := range res.Evidence {
		if strings.HasPrefix(ev.Source, "ci_run__") && ev.Value == "npm install" {
			hasInstall = true
		}
		if strings.HasPrefix(ev.Source, "ci_run__") && ev.Value == "npm test" {
			hasTest = true
		}
	}
	if !hasInstall {
		t.Error("expected 'npm install' command")
	}
	if !hasTest {
		t.Error("expected 'npm test' command")
	}
}

func TestCollector_ExtractsStructuredEvidence(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := `name: CI
on: push
env:
  GLOBAL_KEY: global-value
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      JOB_KEY: job-value
    container:
      image: node:22-alpine
    services:
      postgres:
        image: postgres:15
        ports:
          - "5432:5432"
    defaults:
      run:
        working-directory: ./app
        shell: bash
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Step with env
        env:
          STEP_KEY: step-value
        run: npm test
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	checks := map[string]string{
		"ci_env__workflow__GLOBAL_KEY":              "global-value",
		"ci_env__job__test__JOB_KEY":                "job-value",
		"ci_env__step__test__2__STEP_KEY":           "step-value",
		"ci_service__test__postgres__image":         "postgres:15",
		"ci_service__test__postgres__host_port":     "5432",
		"ci_container__test__image":                 "node:22-alpine",
		"ci_defaults__job__test__working_directory": "./app",
		"ci_defaults__job__test__shell":             "bash",
	}

	found := make(map[string]bool)
	for _, ev := range res.Evidence {
		if expected, ok := checks[ev.Source]; ok && ev.Value == expected {
			found[ev.Source] = true
		}
	}
	for src := range checks {
		if !found[src] {
			t.Errorf("missing expected evidence: %s", src)
		}
	}

	var hasNode bool
	for _, ev := range res.Evidence {
		if strings.HasPrefix(ev.Source, "ci_setup__test__") && strings.Contains(ev.Source, "__setup_node__node_version") && ev.Value == "22" {
			hasNode = true
		}
	}
	if !hasNode {
		t.Error("expected setup-node version evidence")
	}
}

func TestCollector_StepEnvIncludesStepIndex(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - env:
          NODE_ENV: dev
        run: echo step0
      - env:
          NODE_ENV: prod
        run: echo step1
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var hasDev, hasProd bool
	for _, ev := range res.Evidence {
		if ev.Source == "ci_env__step__test__0__NODE_ENV" && ev.Value == "dev" {
			hasDev = true
		}
		if ev.Source == "ci_env__step__test__1__NODE_ENV" && ev.Value == "prod" {
			hasProd = true
		}
	}
	if !hasDev {
		t.Error("expected ci_env__step__test__0__NODE_ENV = dev")
	}
	if !hasProd {
		t.Error("expected ci_env__step__test__1__NODE_ENV = prod")
	}
}

func TestCollector_ExtractsJobScopedContainers(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container: node:20-alpine
    steps:
      - run: npm test
  build:
    runs-on: ubuntu-latest
    container:
      image: golang:1.22
    steps:
      - run: go build
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(yaml), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var hasTest, hasBuild bool
	for _, ev := range res.Evidence {
		if ev.Source == "ci_container__test__image" && ev.Value == "node:20-alpine" {
			hasTest = true
		}
		if ev.Source == "ci_container__build__image" && ev.Value == "golang:1.22" {
			hasBuild = true
		}
	}
	if !hasTest {
		t.Error("expected ci_container__test__image = node:20-alpine")
	}
	if !hasBuild {
		t.Error("expected ci_container__build__image = golang:1.22")
	}
}

func TestCollector_NoWorkflows(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(res.Evidence) != 0 {
		t.Errorf("expected no evidence, got %d", len(res.Evidence))
	}
}
