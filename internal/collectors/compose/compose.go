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

		// Also extract port mappings for M2 port conflict detection
		ports, err := extractPortMappings(path)
		if err == nil {
			for _, p := range ports {
				evidence = append(evidence, schema.Evidence{
					Source: "compose_host_port",
					Value:  p,
				})
			}
		}

		services, err := extractServiceSpecs(path)
		if err == nil {
			for _, svc := range services {
				if svc.Image != "" {
					evidence = append(evidence, schema.Evidence{
						Source: fmt.Sprintf("compose_service__%s__image", sanitizeSource(svc.Name)),
						Value:  svc.Image,
					})
				}
				for _, p := range svc.Ports {
					if p.HostPort != "" {
						evidence = append(evidence, schema.Evidence{
							Source: fmt.Sprintf("compose_service__%s__host_port", sanitizeSource(svc.Name)),
							Value:  p.HostPort,
						})
					}
					if p.ContainerPort != "" {
						evidence = append(evidence, schema.Evidence{
							Source: fmt.Sprintf("compose_service__%s__container_port", sanitizeSource(svc.Name)),
							Value:  p.ContainerPort,
						})
					}
				}
			}
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

type serviceSpec struct {
	Name  string
	Image string
	Ports []portSpec
}

type portSpec struct {
	HostPort      string
	ContainerPort string
}

var (
	// Matches ${VAR}, ${VAR:-default}, ${VAR:?error}, $VAR, etc.
	// Does NOT match $$VAR (escaped)
	composeVarRe = regexp.MustCompile(`\$\$?\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

func extractPortMappings(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var ports []string
	start := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		start = root.Content[0]
	}
	walkYAML(start, "", func(path string, node *yaml.Node) {
		// Only match actual "ports" keys, not substrings like "sports" or "reporting_ports"
		isPortsField := strings.HasSuffix(path, ".ports") || strings.Contains(path, ".ports[")
		if node.Kind == yaml.ScalarNode && isPortsField {
			// Port syntax: "5432:5432", "127.0.0.1:8000:8000", "5432"
			val := strings.TrimSpace(node.Value)
			if val == "" {
				return
			}
			// Only capture explicit host:container mappings
			if strings.Contains(val, ":") {
				parts := strings.Split(val, ":")
				if len(parts) == 2 {
					// "5432:5432" or "127.0.0.1:8000"
					hostPart := strings.TrimSpace(parts[0])
					if strings.Contains(hostPart, ".") {
						// IP:port syntax → host port is the second part
						hostPart = strings.TrimSpace(parts[1])
					}
					if hostPart != "" {
						ports = append(ports, hostPart)
					}
				} else if len(parts) == 3 {
					// "127.0.0.1:8000:8000" → host port is middle part
					hostPart := strings.TrimSpace(parts[1])
					if hostPart != "" {
						ports = append(ports, hostPart)
					}
				}
			}
			// Single port like "5432" is ambiguous; skip for host conflict
		}
	})
	return ports, nil
}

func extractServiceSpecs(path string) ([]serviceSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	start := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		start = root.Content[0]
	}
	if start.Kind != yaml.MappingNode {
		return nil, nil
	}

	var services []serviceSpec
	for i := 0; i < len(start.Content); i += 2 {
		if start.Content[i].Value != "services" || start.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		servicesNode := start.Content[i+1]
		for j := 0; j < len(servicesNode.Content); j += 2 {
			name := servicesNode.Content[j].Value
			node := servicesNode.Content[j+1]
			if node.Kind != yaml.MappingNode {
				continue
			}
			svc := serviceSpec{Name: name}
			for k := 0; k < len(node.Content); k += 2 {
				key := node.Content[k].Value
				val := node.Content[k+1]
				switch key {
				case "image":
					if val.Kind == yaml.ScalarNode {
						svc.Image = strings.TrimSpace(val.Value)
					}
				case "ports":
					svc.Ports = append(svc.Ports, extractServicePorts(val)...)
				}
			}
			services = append(services, svc)
		}
	}
	return services, nil
}

func extractServicePorts(node *yaml.Node) []portSpec {
	switch node.Kind {
	case yaml.SequenceNode:
		ports := make([]portSpec, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				if spec := parsePortSpec(item.Value); spec.HostPort != "" || spec.ContainerPort != "" {
					ports = append(ports, spec)
				}
			}
		}
		return ports
	case yaml.ScalarNode:
		if spec := parsePortSpec(node.Value); spec.HostPort != "" || spec.ContainerPort != "" {
			return []portSpec{spec}
		}
	}
	return nil
}

func parsePortSpec(portStr string) portSpec {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return portSpec{}
	}
	portStr = strings.SplitN(portStr, "/", 2)[0]
	parts := strings.Split(portStr, ":")
	switch len(parts) {
	case 1:
		return portSpec{ContainerPort: strings.TrimSpace(parts[0])}
	case 2:
		return portSpec{HostPort: strings.TrimSpace(parts[0]), ContainerPort: strings.TrimSpace(parts[1])}
	case 3:
		return portSpec{HostPort: strings.TrimSpace(parts[1]), ContainerPort: strings.TrimSpace(parts[2])}
	default:
		return portSpec{}
	}
}

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

func sanitizeSource(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.ReplaceAll(b.String(), "__", "%5F%5F")
}
