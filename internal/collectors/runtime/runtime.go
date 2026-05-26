package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

	if v := parseDotnetSDKVersion(filepath.Join(root, "global.json")); v != "" {
		evidence = append(evidence, schema.Evidence{Source: "global.json", Value: "dotnet " + v})
	}

	for _, packagePath := range packageJSONRuntimePaths(root) {
		source := packageJSONEvidenceSource(root, packagePath)
		pm, engines := parsePackageJSONRuntime(packagePath)
		if pm != "" {
			evidence = append(evidence, schema.Evidence{Source: source, Value: "packageManager: " + pm})
		}
		if engines != "" {
			evidence = append(evidence, schema.Evidence{Source: source, Value: "engines: " + engines})
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

var dotnetSDKVersionRe = regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)

func parseDotnetSDKVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := dotnetSDKVersionRe.FindStringSubmatch(string(data)); m != nil {
		return strings.TrimSpace(m[1])
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
	var pkg struct {
		PackageManager string            `json:"packageManager"`
		Engines        map[string]string `json:"engines"`
	}
	if err := json.Unmarshal(data, &pkg); err == nil {
		packageManager = strings.TrimSpace(pkg.PackageManager)
		if len(pkg.Engines) > 0 {
			keys := make([]string, 0, len(pkg.Engines))
			for key := range pkg.Engines {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, key := range keys {
				value := strings.TrimSpace(pkg.Engines[key])
				if value == "" {
					continue
				}
				parts = append(parts, `"`+key+`": "`+value+`"`)
			}
			engines = strings.Join(parts, ", ")
		}
		return packageManager, engines
	}

	content := string(data)
	if m := packageManagerRe.FindStringSubmatch(content); m != nil {
		packageManager = m[1]
	}
	if m := enginesRe.FindStringSubmatch(content); m != nil {
		engines = strings.TrimSpace(m[1])
	}
	return packageManager, engines
}

func packageJSONRuntimePaths(root string) []string {
	var paths []string
	rootPackage := filepath.Join(root, "package.json")
	if fileExists(rootPackage) {
		paths = append(paths, rootPackage)
	}
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			if shouldSkipRuntimeDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "package.json" || path == rootPackage {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	return paths
}

func shouldSkipRuntimeDir(name string) bool {
	switch name {
	case ".git", ".devdiag", "node_modules", "vendor", "dist", "build", "coverage":
		return true
	default:
		return false
	}
}

func packageJSONEvidenceSource(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "package.json"
	}
	return filepath.ToSlash(rel)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
