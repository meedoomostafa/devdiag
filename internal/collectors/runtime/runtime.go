package runtime

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector reads runtime version pin files and produces expectation-only evidence.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "runtime"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}

	// Node.js .nvmrc
	if v := readFirstLine(filepath.Join(root, ".nvmrc")); v != "" {
		evidence = append(evidence, schema.Evidence{Source: ".nvmrc", Value: "node " + v})
	}

	// Ruby .ruby-version
	if v := readFirstLine(filepath.Join(root, ".ruby-version")); v != "" {
		evidence = append(evidence, schema.Evidence{Source: ".ruby-version", Value: "ruby " + v})
	}

	// Python .python-version
	if v := readFirstLine(filepath.Join(root, ".python-version")); v != "" {
		evidence = append(evidence, schema.Evidence{Source: ".python-version", Value: "python " + v})
	}

	// Go go.mod
	if v := parseGoVersion(filepath.Join(root, "go.mod")); v != "" {
		evidence = append(evidence, schema.Evidence{Source: "go.mod", Value: "go " + v})
	}

	// Rust Cargo.toml
	if v := parseRustVersion(filepath.Join(root, "Cargo.toml")); v != "" {
		evidence = append(evidence, schema.Evidence{Source: "Cargo.toml", Value: "rust " + v})
	}

	// package.json engines / packageManager
	if pm, engines := parsePackageJSONRuntime(filepath.Join(root, "package.json")); pm != "" || engines != "" {
		if pm != "" {
			evidence = append(evidence, schema.Evidence{Source: "package.json", Value: "packageManager: " + pm})
		}
		if engines != "" {
			evidence = append(evidence, schema.Evidence{Source: "package.json", Value: "engines: " + engines})
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

var goVersionRe = regexp.MustCompile(`^go\s+(\d+\.\d+)`)

func parseGoVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if m := goVersionRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

var rustVersionRe = regexp.MustCompile(`(?i)^rust-version\s*=\s*"([^"]+)"`)

func parseRustVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if m := rustVersionRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

var (
	packageManagerRe = regexp.MustCompile(`"packageManager"\s*:\s*"([^"]+)"`)
	enginesRe        = regexp.MustCompile(`"engines"\s*:\s*\{([^}]+)\}`)
)

func parsePackageJSONRuntime(path string) (packageManager, engines string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	content := string(data)
	if m := packageManagerRe.FindStringSubmatch(content); m != nil {
		packageManager = m[1]
	}
	if m := enginesRe.FindStringSubmatch(content); m != nil {
		engines = strings.TrimSpace(m[1])
	}
	return
}
