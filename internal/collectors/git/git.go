package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector uses native git via exec.CommandContext to read repo state.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "git"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}

	// Check if git binary exists
	if _, err := exec.LookPath("git"); err != nil {
		return schema.CollectorResult{
			Name:    c.Name(),
			Status:  schema.CollectorUnavailable,
			Notes:   []string{"git binary not found"},
			Partial: true,
		}, nil
	}

	// Check if this is a git repo
	topLevel, err := gitExec(ctx, root, "rev-parse", "--show-toplevel")
	if err != nil {
		return schema.CollectorResult{
			Name:    c.Name(),
			Status:  schema.CollectorUnavailable,
			Notes:   []string{"not a git repository"},
			Partial: true,
		}, nil
	}
	topLevel = strings.TrimSpace(topLevel)
	evidence = append(evidence, schema.Evidence{Source: "git_toplevel", Value: topLevel})

	// Check if .env is tracked
	trackedOut, trackedErr := gitExec(ctx, root, "ls-files", "--", ".env", ".env.*")
	trackedFiles := []string{}
	if trackedErr == nil {
		for _, line := range strings.Split(strings.TrimSpace(trackedOut), "\n") {
			if line != "" {
				trackedFiles = append(trackedFiles, line)
			}
		}
	}
	var trackedRiskyEnv []string
	var trackedTemplateEnv []string
	for _, file := range trackedFiles {
		if isSafeEnvTemplate(file) {
			trackedTemplateEnv = append(trackedTemplateEnv, file)
			continue
		}
		trackedRiskyEnv = append(trackedRiskyEnv, file)
	}
	if len(trackedRiskyEnv) > 0 {
		evidence = append(evidence, schema.Evidence{Source: "git_tracked_env", Value: strings.Join(trackedRiskyEnv, ", ")})
	}
	if len(trackedTemplateEnv) > 0 {
		evidence = append(evidence, schema.Evidence{Source: "git_tracked_env_template", Value: strings.Join(trackedTemplateEnv, ", ")})
	}

	// Check if .env exists on disk
	envExists := false
	if _, err := os.Stat(filepath.Join(root, ".env")); err == nil {
		envExists = true
	}
	evidence = append(evidence, schema.Evidence{Source: "git_env_exists", Value: boolStr(envExists)})

	// Check if .env is ignored (using git check-ignore)
	ignored := false
	if _, err := gitExec(ctx, root, "check-ignore", "-q", ".env"); err == nil {
		// exit 0 means ignored
		ignored = true
	}
	evidence = append(evidence, schema.Evidence{Source: "git_env_ignored", Value: boolStr(ignored)})

	// Dirty state as informational evidence only
	statusOut, statusErr := gitExec(ctx, root, "status", "--porcelain=v1")
	if statusErr == nil {
		lines := strings.Split(strings.TrimSpace(statusOut), "\n")
		if len(lines) > 0 && lines[0] != "" {
			evidence = append(evidence, schema.Evidence{Source: "git_dirty", Value: "true"})
		} else {
			evidence = append(evidence, schema.Evidence{Source: "git_dirty", Value: "false"})
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
		Notes:    notes,
	}, nil
}

// gitExec runs a git command with timeout via exec.CommandContext.
// Uses direct argv, no shell, and short timeout.
func gitExec(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func isSafeEnvTemplate(path string) bool {
	base := filepath.Base(path)
	if base == ".env" {
		return false
	}
	if !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".schema", ".default", ".defaults"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}
