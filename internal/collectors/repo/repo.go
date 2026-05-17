package repo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
		evidence = append(evidence, packageJSONEvidence(filepath.Join(root, "package.json"))...)
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

	evidence = append(evidence, localCISimulatorEvidence(root)...)
	evidence = append(evidence, localCommandEvidence(root)...)

	// Devcontainer image extraction
	devcontainerPath := filepath.Join(root, ".devcontainer", "devcontainer.json")
	if fileExists(devcontainerPath) {
		img := parseDevcontainerImage(devcontainerPath)
		if img != "" {
			evidence = append(evidence, schema.Evidence{Source: "devcontainer_image", Value: img})
		}
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

// HasPythonSignal returns true if the repo contains Python signals.
func HasPythonSignal(root string) bool {
	if root == "" {
		root = "."
	}
	return fileExists(filepath.Join(root, "requirements.txt")) ||
		fileExists(filepath.Join(root, "pyproject.toml")) ||
		fileExists(filepath.Join(root, "setup.py")) ||
		fileExists(filepath.Join(root, "setup.cfg")) ||
		fileExists(filepath.Join(root, "Pipfile"))
}

// HasCISignal returns true if the repo contains at least one GitHub Actions workflow file.
func HasCISignal(root string) bool {
	if root == "" {
		root = "."
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			return true
		}
	}
	return false
}

func parseDevcontainerImage(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg struct {
		Image string `json:"image"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return cfg.Image
}

func packageJSONEvidence(path string) []schema.Evidence {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		PackageManager string            `json:"packageManager"`
		Scripts        map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var ev []schema.Evidence
	pmName := packageManagerName(pkg.PackageManager)
	if pkg.PackageManager != "" {
		ev = append(ev, schema.Evidence{Source: "repo_package_manager", Value: pkg.PackageManager})
	}
	if pmName == "" {
		pmName = inferPackageManagerFromFiles(filepath.Dir(path))
	}
	for name := range pkg.Scripts {
		ev = append(ev, schema.Evidence{
			Source: "repo_command__package_json__" + sanitizeSource(name),
			Value:  strings.TrimSpace(pmName + " " + name),
		})
	}
	return ev
}

func localCISimulatorEvidence(root string) []schema.Evidence {
	var ev []schema.Evidence
	if fileExists(filepath.Join(root, ".actrc")) {
		ev = append(ev, schema.Evidence{Source: "local_ci_simulator", Value: "act"})
	}
	if fileExists(filepath.Join(root, "wrkflw.toml")) || fileExists(filepath.Join(root, ".wrkflw.yml")) || fileExists(filepath.Join(root, ".wrkflw.yaml")) {
		ev = append(ev, schema.Evidence{Source: "local_ci_simulator", Value: "wrkflw"})
	}
	return ev
}

func localCommandEvidence(root string) []schema.Evidence {
	var ev []schema.Evidence
	ev = append(ev, targetCommandEvidence(filepath.Join(root, "Makefile"), "repo_command__makefile__", "make")...)
	ev = append(ev, targetCommandEvidence(filepath.Join(root, "Taskfile.yml"), "repo_command__taskfile__", "task")...)
	ev = append(ev, targetCommandEvidence(filepath.Join(root, "Taskfile.yaml"), "repo_command__taskfile__", "task")...)
	ev = append(ev, targetCommandEvidence(filepath.Join(root, "justfile"), "repo_command__justfile__", "just")...)
	ev = append(ev, readmeCommandEvidence(filepath.Join(root, "README.md"))...)
	return ev
}

var targetRe = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.-]+)\s*:`)

func targetCommandEvidence(path, sourcePrefix, command string) []schema.Evidence {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ev []schema.Evidence
	matches := targetRe.FindAllStringSubmatch(string(data), -1)
	for _, m := range matches {
		name := m[1]
		if name == "tasks" || name == "cmds" || strings.HasPrefix(name, ".") {
			continue
		}
		ev = append(ev, schema.Evidence{
			Source: sourcePrefix + sanitizeSource(name),
			Value:  command + " " + name,
		})
	}
	return ev
}

var readmeCommandRe = regexp.MustCompile("`((?:npm|pnpm|yarn|bun|make|task|just) [^`]+)`")

func readmeCommandEvidence(path string) []schema.Evidence {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ev []schema.Evidence
	matches := readmeCommandRe.FindAllStringSubmatch(string(data), -1)
	for _, m := range matches {
		cmd := strings.TrimSpace(m[1])
		ev = append(ev, schema.Evidence{
			Source: "repo_command__readme__" + sanitizeSource(cmd),
			Value:  cmd,
		})
	}
	return ev
}

func packageManagerName(pm string) string {
	if idx := strings.Index(pm, "@"); idx != -1 {
		return pm[:idx]
	}
	return pm
}

func inferPackageManagerFromFiles(root string) string {
	switch {
	case fileExists(filepath.Join(root, "pnpm-lock.yaml")):
		return "pnpm"
	case fileExists(filepath.Join(root, "yarn.lock")):
		return "yarn"
	case fileExists(filepath.Join(root, "bun.lock")) || fileExists(filepath.Join(root, "bun.lockb")):
		return "bun"
	default:
		return "npm"
	}
}

func sanitizeSource(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
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
