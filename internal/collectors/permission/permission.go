package permission

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks repo-relevant file permissions.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "permission"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}

	// Check repo root write access
	if tmpFile, err := os.CreateTemp(root, ".devdiag-write-test-"); err == nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		evidence = append(evidence, schema.Evidence{
			Source: "host_repo_writable",
			Value:  "true",
		})
	} else {
		evidence = append(evidence, schema.Evidence{
			Source: "host_repo_writable",
			Value:  "false",
		})
	}

	// Check referenced scripts from package.json
	scripts := findPackageJSONScripts(root)
	for _, script := range scripts {
		path := filepath.Join(root, script)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			mode := fi.Mode()
			if mode&0111 == 0 {
				evidence = append(evidence, schema.Evidence{
					Source: "host_script_not_executable",
					Value:  script,
				})
			}
			// Check root ownership
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat.Uid == 0 {
				evidence = append(evidence, schema.Evidence{
					Source: "host_file_root_owned",
					Value:  script,
				})
			}
		}
	}

	// Check Makefile / Taskfile / justfile presence and readability
	for _, name := range []string{"Makefile", "Taskfile.yml", "Taskfile.yaml", "justfile", "Justfile"} {
		path := filepath.Join(root, name)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			if fi.Mode()&0444 != 0 {
				evidence = append(evidence, schema.Evidence{
					Source: "host_build_file_readable",
					Value:  name,
				})
			}
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}

func findPackageJSONScripts(root string) []string {
	var scripts []string
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return scripts
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return scripts
	}

	seen := map[string]bool{}
	for _, cmd := range pkg.Scripts {
		// Extract simple local file references from commands
		// e.g. "./bin/setup.sh", "../bin/build.sh"
		for _, field := range strings.Fields(cmd) {
			field = strings.Trim(field, `"'`)
			if strings.HasPrefix(field, "./") {
				path := strings.TrimPrefix(field, "./")
				if path != "" && !seen[path] {
					seen[path] = true
					scripts = append(scripts, path)
				}
			} else if strings.HasPrefix(field, "../") {
				// Preserve parent-directory traversal
				if !seen[field] {
					seen[field] = true
					scripts = append(scripts, field)
				}
			}
		}
	}
	return scripts
}
