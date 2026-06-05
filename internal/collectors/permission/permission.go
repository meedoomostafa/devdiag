package permission

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"golang.org/x/sys/unix"
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

	// Check repo root write access without creating files (no mutation)
	if err := unix.Access(root, unix.W_OK); err == nil {
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
			if stat, ok := fi.Sys().(*unix.Stat_t); ok && stat.Uid == 0 {
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
		for _, script := range directPackageScriptExecutables(cmd) {
			if script != "" && !seen[script] {
				seen[script] = true
				scripts = append(scripts, script)
			}
		}
	}
	return scripts
}

func directPackageScriptExecutables(cmd string) []string {
	var scripts []string
	commandPosition := true
	for _, field := range strings.Fields(cmd) {
		field = strings.Trim(field, `"'`)
		if field == "" {
			continue
		}
		if isShellCommandSeparator(field) {
			commandPosition = true
			continue
		}
		if commandPosition && isEnvAssignment(field) {
			continue
		}
		candidate, separatorAfter := trimTrailingCommandSeparator(field)
		if commandPosition {
			if script, ok := localScriptRef(candidate); ok {
				scripts = append(scripts, script)
			}
		}
		commandPosition = separatorAfter
	}
	return scripts
}

func localScriptRef(field string) (string, bool) {
	if strings.HasPrefix(field, "./") {
		path := strings.TrimPrefix(field, "./")
		return path, path != ""
	}
	if strings.HasPrefix(field, "../") {
		return field, true
	}
	return "", false
}

func isShellCommandSeparator(field string) bool {
	switch field {
	case "&&", "||", ";", "|":
		return true
	default:
		return false
	}
}

func trimTrailingCommandSeparator(field string) (string, bool) {
	for _, suffix := range []string{"&&", "||", ";", "|"} {
		if strings.HasSuffix(field, suffix) && len(field) > len(suffix) {
			return strings.TrimSuffix(field, suffix), true
		}
	}
	return field, false
}

func isEnvAssignment(field string) bool {
	if strings.HasPrefix(field, "-") {
		return false
	}
	idx := strings.Index(field, "=")
	if idx <= 0 {
		return false
	}
	key := field[:idx]
	for i, r := range key {
		if i == 0 {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_') {
				return false
			}
			continue
		}
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}
