package cache

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollectorNoCaches(t *testing.T) {
	c := &Collector{
		Runner:  cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{}),
		homeDir: t.TempDir(),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || *res.Applicable {
		t.Fatal("expected Applicable=false")
	}
}

func TestCollectorPipCache(t *testing.T) {
	home := t.TempDir()
	pipDir := filepath.Join(home, ".cache", "pip")
	if err := os.MkdirAll(pipDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"du -sb " + pipDir: {
				Command:  "du",
				ExitCode: 0,
				Stdout:   "10485760\t" + pipDir + "\n",
			},
		}),
		homeDir: home,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Applicable == nil || !*res.Applicable {
		t.Fatal("expected Applicable=true")
	}
	assertEvidence(t, res.Evidence, "cache_pip_path", pipDir)
	assertEvidence(t, res.Evidence, "cache_pip_size_mb", "10")
	assertEvidence(t, res.Evidence, "cache_pip_writable", "true")
}

func TestCollectorDockerCache(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"docker system df": {
				Command:  "docker",
				ExitCode: 0,
				Stdout: "TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE\n" +
					"Images          10        5         2.5GB     1.2GB\n",
			},
		}),
		homeDir: t.TempDir(),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "cache_docker_path", "docker_system")
	assertEvidence(t, res.Evidence, "cache_docker_size_mb", "2.5GB")
}

func TestCollectorDockerCacheJSON(t *testing.T) {
	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"docker system df --format json": {
				Command:  "docker",
				ExitCode: 0,
				Stdout:   `{"Type":"Images","TotalCount":10,"Active":5,"Size":"3.1GB","Reclaimable":"1.5GB"}`,
			},
		}),
		homeDir: t.TempDir(),
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "cache_docker_path", "docker_system")
	assertEvidence(t, res.Evidence, "cache_docker_size_mb", "3.1GB")
}

func TestParseDockerSystemDfJSON(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name:   "images size",
			stdout: `{"Type":"Images","Size":"2.5GB"}`,
			want:   "2.5GB",
		},
		{
			name:   "spaces in json",
			stdout: `{"Type": "Images", "Size": "1.2GB"}`,
			want:   "1.2GB",
		},
		{
			name:   "no images",
			stdout: `{"Type":"Build Cache","Size":"500MB"}`,
			want:   "",
		},
		{
			name:   "empty",
			stdout: "",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDockerSystemDfJSON(tt.stdout)
			if got != tt.want {
				t.Fatalf("parseDockerSystemDfJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseDockerSystemDfTabular(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name: "standard images row",
			stdout: "TYPE            TOTAL   ACTIVE  SIZE      RECLAIMABLE\n" +
				"Images          10      5       2.5GB     1.2GB\n",
			want: "2.5GB",
		},
		{
			name: "local volumes row",
			stdout: "TYPE            TOTAL     ACTIVE  SIZE      RECLAIMABLE\n" +
				"Local Volumes   5         2       100MB     50MB\n",
			want: "100MB",
		},
		{
			name:   "empty",
			stdout: "",
			want:   "",
		},
		{
			name:   "missing images",
			stdout: "TYPE            TOTAL   ACTIVE  SIZE      RECLAIMABLE\n",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := parseDockerSystemDfTabular(tt.stdout)
			if tt.want == "" {
				if entry != nil {
					t.Fatalf("expected nil entry, got %+v", entry)
				}
				return
			}
			if entry == nil {
				t.Fatalf("expected non-nil entry")
			}
			if entry.SizeMB != tt.want {
				t.Fatalf("SizeMB = %q, want %q", entry.SizeMB, tt.want)
			}
		})
	}
}

func TestCollectorNPMConditional(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	npmDir := filepath.Join(home, ".npm")
	if err := os.MkdirAll(npmDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"du -sb " + npmDir: {
				Command:  "du",
				ExitCode: 0,
				Stdout:   "5242880\t" + npmDir + "\n",
			},
		}),
		homeDir:  home,
		RepoRoot: repo,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "cache_npm_path", npmDir)
	assertEvidence(t, res.Evidence, "cache_npm_size_mb", "5")
}

func TestCollectorNPMWithoutPackageJSON(t *testing.T) {
	home := t.TempDir()
	npmDir := filepath.Join(home, ".npm")
	if err := os.MkdirAll(npmDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := &Collector{
		Runner:   cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{}),
		homeDir:  home,
		RepoRoot: t.TempDir(), // no package.json
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, ev := range res.Evidence {
		if ev.Source == "cache_npm_path" {
			t.Fatalf("expected no npm cache evidence without package.json")
		}
	}
}

func TestCollectorGoConditional(t *testing.T) {
	t.Setenv("GOCACHE", "")

	home := t.TempDir()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module test"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	goDir := filepath.Join(home, ".cache", "go-build")
	if err := os.MkdirAll(goDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"du -sb " + goDir: {
				Command:  "du",
				ExitCode: 0,
				Stdout:   "2097152\t" + goDir + "\n",
			},
		}),
		homeDir:  home,
		RepoRoot: repo,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "cache_go_path", goDir)
	assertEvidence(t, res.Evidence, "cache_go_size_mb", "2")
}

func TestCollectorDUTimeout(t *testing.T) {
	home := t.TempDir()
	pipDir := filepath.Join(home, ".cache", "pip")
	if err := os.MkdirAll(pipDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := &Collector{
		Runner: cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"du -sb " + pipDir: {
				Command:  "du",
				TimedOut: true,
				ExitCode: -1,
			},
		}),
		homeDir: home,
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEvidence(t, res.Evidence, "cache_pip_size_mb", "unknown")
}

func assertEvidence(t *testing.T, evidence []schema.Evidence, source, want string) {
	t.Helper()
	for _, ev := range evidence {
		if ev.Source == source {
			if ev.Value != want {
				t.Fatalf("evidence %q = %q, want %q", source, ev.Value, want)
			}
			return
		}
	}
	t.Fatalf("missing evidence %q (want %q)", source, want)
}
