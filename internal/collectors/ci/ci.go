package ci

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"gopkg.in/yaml.v3"
)

// Collector scans CI workflow files and extracts commands as evidence.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "ci"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}

	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		// No CI workflows is not an error, just no evidence
		return schema.CollectorResult{
			Name:   c.Name(),
			Status: schema.CollectorOK,
		}, nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		path := filepath.Join(workflowDir, name)
		commands, err := extractRunCommands(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("failed to parse %s: %v", name, err))
			continue
		}

		for _, cmd := range commands {
			evidence = append(evidence, schema.Evidence{
				Source: name,
				Value:  cmd,
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

func extractRunCommands(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	// Document node content is in root.Content[0]
	start := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		start = root.Content[0]
	}

	var commands []string
	walkYAML(start, func(node *yaml.Node) {
		if node.Kind == yaml.MappingNode {
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				val := node.Content[i+1]
				if key.Kind == yaml.ScalarNode && key.Value == "run" && val.Kind == yaml.ScalarNode {
					commands = append(commands, strings.TrimSpace(val.Value))
				}
			}
		}
	})

	return commands, nil
}

func walkYAML(node *yaml.Node, fn func(*yaml.Node)) {
	fn(node)
	switch node.Kind {
	case yaml.MappingNode:
		for _, child := range node.Content {
			walkYAML(child, fn)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkYAML(child, fn)
		}
	}
}
