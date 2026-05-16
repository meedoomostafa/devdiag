package composestatus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
