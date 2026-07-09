package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_UsesInjectedRunner(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	fake := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"git rev-parse --show-toplevel": {Stdout: "/repo\n", ExitCode: 0},
		"git ls-files -- .env .env.*":   {Stdout: ".env\n", ExitCode: 0},
		"git check-ignore -q .env":      {ExitCode: 1},
		"git status --porcelain=v1":     {Stdout: "", ExitCode: 0},
	})
	c := &Collector{Root: "/tmp", Runner: fake}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	var tracked, ignored string
	for _, ev := range res.Evidence {
		switch ev.Source {
		case "git_tracked_env":
			tracked = ev.Value
		case "git_env_ignored":
			ignored = ev.Value
		}
	}
	if tracked != ".env" {
		t.Errorf("git_tracked_env = %q, want .env", tracked)
	}
	if ignored != "false" {
		t.Errorf("git_env_ignored = %q, want false", ignored)
	}
	for _, call := range fake.Calls {
		if call.Dir != "/tmp" {
			t.Errorf("call %v ran in dir %q, want /tmp", call.Args, call.Dir)
		}
	}
}

func TestCollector_NonGitRepo(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorUnavailable {
		t.Errorf("status = %s, want unavailable", res.Status)
	}
}

func TestCollector_TrackedEnv(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	initGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=value\n"), 0644)
	runGit(t, dir, "add", ".env")
	runGit(t, dir, "commit", "-m", "add env")

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var hasTracked bool
	for _, ev := range res.Evidence {
		if ev.Source == "git_tracked_env" && ev.Value != "" {
			hasTracked = true
		}
	}
	if !hasTracked {
		t.Errorf("expected tracked .env evidence, got: %v", res.Evidence)
	}
}

func TestCollector_TrackedEnvTemplateIsInformational(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	initGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, ".env.example"), []byte("SECRET=\n"), 0644)
	runGit(t, dir, "add", ".env.example")
	runGit(t, dir, "commit", "-m", "add env template")

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var hasTrackedTemplate bool
	for _, ev := range res.Evidence {
		if ev.Source == "git_tracked_env" {
			t.Fatalf("tracked env template was reported as risky env evidence: %v", res.Evidence)
		}
		if ev.Source == "git_tracked_env_template" && ev.Value == ".env.example" {
			hasTrackedTemplate = true
		}
	}
	if !hasTrackedTemplate {
		t.Errorf("expected tracked env template evidence, got: %v", res.Evidence)
	}
}

func TestCollector_EnvIgnored(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	initGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=value\n"), 0644)
	runGit(t, dir, "add", ".gitignore")
	runGit(t, dir, "commit", "-m", "add gitignore")

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var ignored bool
	for _, ev := range res.Evidence {
		if ev.Source == "git_env_ignored" && ev.Value == "true" {
			ignored = true
		}
	}
	if !ignored {
		t.Errorf("expected .env to be ignored, got: %v", res.Evidence)
	}
}

func TestCollector_DirtyState_InfoOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	initGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var dirtyFound bool
	for _, ev := range res.Evidence {
		if ev.Source == "git_dirty" {
			dirtyFound = true
		}
	}
	if !dirtyFound {
		t.Error("expected git_dirty evidence")
	}
}

func TestCollector_GitignorePattern(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	initGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env*\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".env.local"), []byte("LOCAL=1\n"), 0644)
	runGit(t, dir, "add", ".gitignore")
	runGit(t, dir, "commit", "-m", "add gitignore")

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var ignored bool
	for _, ev := range res.Evidence {
		if ev.Source == "git_env_ignored" && ev.Value == "true" {
			ignored = true
		}
	}
	if !ignored {
		t.Errorf("expected .env.local to be ignored via .env* pattern, got: %v", res.Evidence)
	}
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v failed: %v", args, err)
	}
}
