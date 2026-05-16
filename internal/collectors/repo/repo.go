package repo

import (
	"context"
	"os"
	"path/filepath"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector detects repo structure, package managers, runtimes, and signals.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "repo"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}
	signals := []string{}

	// Package manager signals
	if fileExists(filepath.Join(root, "go.mod")) {
		signals = append(signals, "go")
		evidence = append(evidence, schema.Evidence{Source: "go.mod", Value: "Go module detected"})
	}
	if fileExists(filepath.Join(root, "package.json")) {
		signals = append(signals, "nodejs")
		evidence = append(evidence, schema.Evidence{Source: "package.json", Value: "Node.js project detected"})
	}
	if fileExists(filepath.Join(root, "Cargo.toml")) {
		signals = append(signals, "rust")
		evidence = append(evidence, schema.Evidence{Source: "Cargo.toml", Value: "Rust project detected"})
	}
	if fileExists(filepath.Join(root, "requirements.txt")) || fileExists(filepath.Join(root, "pyproject.toml")) {
		signals = append(signals, "python")
		evidence = append(evidence, schema.Evidence{Source: "python_files", Value: "Python project detected"})
	}

	// Package manager lockfiles
	lockfiles := []string{}
	for _, f := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "go.sum", "Cargo.lock", "poetry.lock", "Pipfile.lock"} {
		if fileExists(filepath.Join(root, f)) {
			lockfiles = append(lockfiles, f)
		}
	}
	if len(lockfiles) > 0 {
		evidence = append(evidence, schema.Evidence{Source: "lockfiles", Value: joinStrings(lockfiles, ", ")})
	}

	// Container signals
	if fileExists(filepath.Join(root, "Dockerfile")) || fileExists(filepath.Join(root, "dockerfile")) {
		signals = append(signals, "docker")
		evidence = append(evidence, schema.Evidence{Source: "Dockerfile", Value: "Docker build detected"})
	}
	if fileExists(filepath.Join(root, "compose.yaml")) || fileExists(filepath.Join(root, "docker-compose.yml")) || fileExists(filepath.Join(root, "docker-compose.yaml")) {
		signals = append(signals, "compose")
		evidence = append(evidence, schema.Evidence{Source: "compose", Value: "Compose config detected"})
	}

	// Runtime version pins
	pins := map[string]string{
		".nvmrc":          "node",
		".ruby-version":   "ruby",
		".python-version": "python",
	}
	for file, runtime := range pins {
		if fileExists(filepath.Join(root, file)) {
			signals = append(signals, runtime+"_pin")
			evidence = append(evidence, schema.Evidence{Source: file, Value: runtime + " version pin detected"})
		}
	}

	// Monorepo signals
	if fileExists(filepath.Join(root, "pnpm-workspace.yaml")) || fileExists(filepath.Join(root, "yarn-workspaces")) {
		signals = append(signals, "workspace")
		evidence = append(evidence, schema.Evidence{Source: "workspace", Value: "Workspace/monorepo detected"})
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
		Notes:    notes,
	}, nil
}

// HasDockerSignal returns true if the repo contains Docker/Compose signals.
func HasDockerSignal(root string) bool {
	if root == "" {
		root = "."
	}
	return fileExists(filepath.Join(root, "Dockerfile")) ||
		fileExists(filepath.Join(root, "dockerfile")) ||
		fileExists(filepath.Join(root, "compose.yaml")) ||
		fileExists(filepath.Join(root, "docker-compose.yml")) ||
		fileExists(filepath.Join(root, "docker-compose.yaml")) ||
		fileExists(filepath.Join(root, ".devcontainer/devcontainer.json"))
}

// HasPodmanSignal returns true if the repo contains Podman signals.
func HasPodmanSignal(root string) bool {
	if root == "" {
		root = "."
	}
	return fileExists(filepath.Join(root, "Containerfile")) ||
		fileExists(filepath.Join(root, "containerfile")) ||
		fileExists(filepath.Join(root, ".podman/containers.conf")) ||
		fileExists(filepath.Join(root, "podman-compose.yml")) ||
		fileExists(filepath.Join(root, "podman-compose.yaml"))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
