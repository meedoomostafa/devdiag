package hostruntime

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks installed runtime versions on the host.
type Collector struct{}

func (c *Collector) Name() string {
	return "host_runtime"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	runtimes := []struct {
		name    string
		binary  string
		args    []string
		extract func(string) string
	}{
		{"node", "node", []string{"--version"}, extractPrefix("v")},
		{"python", "python3", []string{"--version"}, extractPrefix("")},
		{"python", "python", []string{"--version"}, extractPrefix("")},
		{"go", "go", []string{"version"}, extractGoVersion},
		{"rustc", "rustc", []string{"--version"}, extractRustcVersion},
		{"dotnet", "dotnet", []string{"--version"}, extractPrefix("")},
	}

	seen := map[string]bool{}
	for _, rt := range runtimes {
		if seen[rt.name] {
			continue
		}

		path, err := exec.LookPath(rt.binary)
		if err != nil {
			continue
		}

		seen[rt.name] = true

		// Resolve absolute path; LookPath may return relative paths
		absPath := path
		if !filepath.IsAbs(path) {
			if p, err := filepath.Abs(path); err == nil {
				absPath = p
			}
		}

		evidence = append(evidence, schema.Evidence{
			Source: fmt.Sprintf("host_%s_path", rt.name),
			Value:  absPath,
		})

		// Detect version manager from path
		if hint := detectVersionManager(absPath); hint != "" {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("host_%s_manager", rt.name),
				Value:  hint,
			})
		}

		// Run version command with timeout (plan budget: 300–1000ms)
		cmdCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		out, err := exec.CommandContext(cmdCtx, rt.binary, rt.args...).Output()
		cancel()
		if err != nil {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("host_%s_version", rt.name),
				Value:  "",
			})
			continue
		}

		version := rt.extract(strings.TrimSpace(string(out)))
		evidence = append(evidence, schema.Evidence{
			Source: fmt.Sprintf("host_%s_version", rt.name),
			Value:  version,
		})
	}

	// For any required runtime that was not seen, mark as missing.
	required := []string{"node", "python", "go", "rustc", "dotnet"}
	for _, name := range required {
		if !seen[name] {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("host_%s_path", name),
				Value:  "",
			})
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("host_%s_missing", name),
				Value:  "true",
			})
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}

func extractPrefix(prefix string) func(string) string {
	return func(s string) string {
		s = strings.TrimSpace(s)
		if prefix != "" && strings.HasPrefix(s, prefix) {
			return s[len(prefix):]
		}
		// For "Python 3.12.2" style output, extract the version part
		parts := strings.Fields(s)
		if len(parts) > 1 {
			return parts[len(parts)-1]
		}
		return s
	}
}

func extractGoVersion(s string) string {
	// "go version go1.23.4 linux/amd64"
	parts := strings.Fields(s)
	for _, p := range parts {
		if strings.HasPrefix(p, "go") && len(p) > 2 {
			return p[2:]
		}
	}
	return ""
}

func extractRustcVersion(s string) string {
	// "rustc 1.75.0 (82e1608df 2024-12-21)"
	parts := strings.Fields(s)
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func detectVersionManager(path string) string {
	path = strings.ToLower(path)
	hints := []struct {
		substr string
		name   string
	}{
		{"/.asdf/shims/", "asdf"},
		{"/.local/share/mise/shims/", "mise"},
		{"/.pyenv/shims/", "pyenv"},
		{"/.pyenv/bin/", "pyenv"},
		{"/.volta/bin/", "volta"},
		{"/.volta/tools/", "volta"},
		{"/.nvm/versions/", "nvm"},
		{"/.fnm/", "fnm"},
		{"/usr/local/bin/", ""},
		{"/usr/bin/", ""},
	}
	for _, h := range hints {
		if h.name != "" && strings.Contains(path, h.substr) {
			return h.name
		}
	}
	return ""
}
