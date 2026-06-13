package composestatus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_NoComposeFile_ApplicableFalse(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable != false {
		t.Errorf("expected applicable=false when no compose file, got: %v", res.Applicable)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("expected status ok, got %s", res.Status)
	}
}

func TestCollector_ComposeFileDetected(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  api:\n    image: nginx\n"), 0644)
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Applicable != nil && !*res.Applicable {
		t.Errorf("expected applicable when compose file exists")
	}
	// Expect compose_file evidence
	var hasComposeFile bool
	for _, ev := range res.Evidence {
		if ev.Source == "compose_file" {
			hasComposeFile = true
		}
	}
	if !hasComposeFile {
		t.Errorf("expected compose_file evidence, got: %v", res.Evidence)
	}
}

func TestCollector_BindMountSourceChecked(t *testing.T) {
	dir := t.TempDir()
	// Create a compose file with a bind mount
	compose := `services:
  api:
    image: nginx
    volumes:
      - "./data:/data"
`
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0644)
	// Note: ./data does not exist, so bind mount source should be marked false
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	var hasBindMountEvidence bool
	for _, ev := range res.Evidence {
		if strings.Contains(ev.Source, "bind_mount_source") {
			hasBindMountEvidence = true
			if !strings.HasSuffix(ev.Value, "=false") {
				t.Errorf("expected bind mount source missing (=false), got: %s", ev.Value)
			}
		}
	}
	if !hasBindMountEvidence {
		t.Logf("bind mount evidence may not appear if docker compose config is unavailable; evidence: %v", res.Evidence)
	}
}

func TestCollector_UsesCommandRunnerWithRepoDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  api:\n    image: nginx\n"), 0644); err != nil {
		t.Fatalf("write compose: %v", err)
	}
	bindSource := filepath.Join(dir, "data")
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker compose config --format json": {
			Command:  "docker",
			ExitCode: 0,
			Stdout: `{
				"services": {
					"api": {
						"image": "nginx",
						"ports": ["8080:80"],
						"volumes": [{"type":"bind","source":"` + bindSource + `","target":"/data"}]
					}
				}
			}`,
		},
		"docker compose ps -a --format json": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   `[{"Service":"api","State":"running","Health":"healthy"}]`,
		},
	})

	c := &Collector{Root: dir, Runner: runner}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %s, want ok; notes=%v", res.Status, res.Notes)
	}
	assertComposeStatusEvidence(t, res.Evidence, "compose_service_api_image", "nginx")
	assertComposeStatusEvidence(t, res.Evidence, "compose_service_api_host_port", "8080")
	assertComposeStatusEvidence(t, res.Evidence, "compose_service_api_bind_mount_source", bindSource+"=false")
	assertComposeStatusEvidence(t, res.Evidence, "compose_service_api_status", "running")
	for _, call := range runner.Calls {
		if call.Dir != dir {
			t.Fatalf("command %s ran in dir %q, want %q", call.Command, call.Dir, dir)
		}
	}
}

func assertComposeStatusEvidence(t *testing.T, evidence []schema.Evidence, source, want string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source {
			if ev.Value != want {
				t.Fatalf("evidence %q = %q, want %q", source, ev.Value, want)
			}
			return
		}
	}
	t.Fatalf("missing evidence %q", source)
}
