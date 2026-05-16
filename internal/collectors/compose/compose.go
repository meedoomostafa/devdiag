package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"gopkg.in/yaml.v3"
)

// Collector parses compose files and detects env variable references.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "compose"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}

	for _, filename := range []string{"compose.yaml", "docker-compose.yml", "docker-compose.yaml"} {
		path := filepath.Join(root, filename)
		if _, err := os.Stat(path); err != nil {
			continue
		}

		refs, err := extractEnvRefs(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("failed to parse %s: %v", filename, err))
			continue
		}

		for _, ref := range refs {
			evidence = append(evidence, schema.Evidence{
				Source: filename + ":" + fmt.Sprintf("%d", ref.Line),
				Value:  fmt.Sprintf("%s references %s", ref.Path, ref.Raw),
			})
		}
	}

	status := schema.CollectorOK
	if len(notes) > 0 {
		status = schema.CollectorPartial
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   status,
		Evidence: evidence,
		Notes:    notes,
	}, nil
}

// envRef represents a discovered env variable reference.
type envRef struct {
	Var  string
	Raw  string
	Path string // e.g. services.api.environment.DATABASE_URL
	Line int
}

var (
	// Matches ${VAR}, ${VAR:-default}, ${VAR:?error}, $VAR, etc.
	// Does NOT match $$VAR (escaped)
	composeVarRe = regexp.MustCompile(`\$\$?\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

func extractEnvRefs(path string) ([]envRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var refs []envRef
	// root is a Document node; actual content is in root.Content[0]
	start := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		start = root.Content[0]
	}
	walkYAML(start, "", func(path string, node *yaml.Node) {
		if node.Kind == yaml.ScalarNode {
			matches := composeVarRe.FindAllStringSubmatchIndex(node.Value, -1)
			for _, m := range matches {
				raw := node.Value[m[0]:m[1]]
				// Skip escaped $$VAR: match is preceded by another $
				if m[0] > 0 && node.Value[m[0]-1] == '$' {
					continue
				}
				// Skip $${VAR}: match itself starts with $$
				if strings.HasPrefix(raw, "$$") {
					continue
				}
				varName := extractVarName(raw)
				if varName != "" {
					refs = append(refs, envRef{
						Var:  varName,
						Raw:  raw,
						Path: path,
						Line: node.Line,
					})
				}
			}
		}
	})

	return refs, nil
}

func walkYAML(node *yaml.Node, path string, fn func(string, *yaml.Node)) {
	fn(path, node)

	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			newPath := path
			if key.Kind == yaml.ScalarNode {
				if newPath != "" {
					newPath += "."
				}
				newPath += key.Value
			}
			walkYAML(val, newPath, fn)
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			walkYAML(child, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	}
}

// extractVarName extracts the variable name from a compose interpolation.
// ${VAR} -> VAR, ${VAR:-default} -> VAR, $VAR -> VAR
func extractVarName(raw string) string {
	raw = strings.TrimPrefix(raw, "$")
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSuffix(raw, "}")
	// Strip modifier suffixes
	for _, sep := range []string{":-", "-", ":?", "?", ":+", "+"} {
		if idx := strings.Index(raw, sep); idx != -1 {
			raw = raw[:idx]
			break
		}
	}
	return strings.TrimSpace(raw)
}
