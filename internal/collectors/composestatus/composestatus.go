package composestatus

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks Compose service status, config validity, bind mounts, and stale containers.
type Collector struct {
	Root string // repo root
}

func (c *Collector) Name() string {
	return "compose_status"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}

	// Determine if compose file exists
	composeFile := ""
	for _, f := range []string{"compose.yaml", "docker-compose.yml", "docker-compose.yaml"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			composeFile = f
			break
		}
	}
	if composeFile == "" {
		// No compose file in this repo; collector is not applicable for compose-specific checks
		// but we still check for Dockerfile-only repos via docker collector
		applicable := false
		return schema.CollectorResult{
			Name:       c.Name(),
			Status:     schema.CollectorOK,
			Applicable: &applicable,
			Evidence:   evidence,
		}, nil
	}

	evidence = append(evidence, schema.Evidence{Source: "compose_file", Value: composeFile})

	// Determine project name precedence
	projectName := resolveProjectName(root, composeFile)
	if projectName != "" {
		evidence = append(evidence, schema.Evidence{Source: "compose_project_name", Value: projectName})
	}

	// docker compose config with strict timeout (only extracted facts, no raw dump)
	cmdCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	out, err := exec.CommandContext(cmdCtx, "docker", "compose", "config", "--format", "json").Output()
	cancel()
	if err != nil {
		notes = append(notes, fmt.Sprintf("docker compose config failed: %v", err))
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorPartial,
			Evidence: evidence,
			Notes:    notes,
		}, nil
	}

	var cfg composeConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		notes = append(notes, fmt.Sprintf("compose config parse failed: %v", err))
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorPartial,
			Evidence: evidence,
			Notes:    notes,
		}, nil
	}

	// Extract facts only: services, profiles, env_file, ports, bind mounts, container_name, healthcheck
	for svcName, svc := range cfg.Services {
		evidence = append(evidence, schema.Evidence{
			Source: fmt.Sprintf("compose_service_%s_image", svcName),
			Value:  svc.Image,
		})
		if svc.ContainerName != "" {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("compose_service_%s_container_name", svcName),
				Value:  svc.ContainerName,
			})
		}
		if len(svc.EnvFile) > 0 {
			for _, ef := range svc.EnvFile {
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("compose_service_%s_env_file", svcName),
					Value:  ef,
				})
			}
		}
		if svc.HealthCheck != nil {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("compose_service_%s_healthcheck", svcName),
				Value:  "present",
			})
		}
		// Port mappings
		for _, port := range svc.Ports {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("compose_service_%s_host_port", svcName),
				Value:  extractHostPort(port),
			})
		}
		// Bind mounts
		for _, vol := range svc.Volumes {
			if vol.Type == "bind" || vol.Type == "" {
				exists := "false"
				if vol.Source != "" {
					if _, err := os.Stat(vol.Source); err == nil {
						exists = "true"
					}
				}
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("compose_service_%s_bind_mount_source", svcName),
					Value:  fmt.Sprintf("%s=%s", vol.Source, exists),
				})
			}
		}
	}

	// docker compose ps --format json for service status
	cmdCtx, cancel = context.WithTimeout(ctx, 2000*time.Millisecond)
	out, err = exec.CommandContext(cmdCtx, "docker", "compose", "ps", "--format", "json").Output()
	cancel()
	if err == nil {
		services := parseComposePS(out)
		for _, s := range services {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("compose_service_%s_status", s.Service),
				Value:  s.State,
			})
			if s.Health != "" {
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("compose_service_%s_health", s.Service),
					Value:  s.Health,
				})
			}
		}
	} else {
		notes = append(notes, fmt.Sprintf("docker compose ps failed: %v", err))
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

// resolveProjectName determines the Compose project name with Docker Compose precedence.
func resolveProjectName(root, composeFile string) string {
	// 1. COMPOSE_PROJECT_NAME from environment
	if v := os.Getenv("COMPOSE_PROJECT_NAME"); v != "" {
		return v
	}
	// 2. .env file in repo root
	if v := readEnvValue(filepath.Join(root, ".env"), "COMPOSE_PROJECT_NAME"); v != "" {
		return v
	}
	// 3. name: field in compose.yaml (best-effort parse)
	if v := readComposeName(filepath.Join(root, composeFile)); v != "" {
		return v
	}
	// 4. repo directory basename
	return filepath.Base(root)
}

func readEnvValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	prefix := key + "="
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func readComposeName(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Best-effort: look for "name:" at top level
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		}
	}
	return ""
}

func extractHostPort(port string) string {
	// "5432:5432" -> "5432"
	// "127.0.0.1:8000:8000" -> "8000"
	// "8000" -> "8000"
	parts := strings.Split(port, ":")
	if len(parts) == 2 {
		hostPart := strings.TrimSpace(parts[0])
		if strings.Contains(hostPart, ".") {
			return strings.TrimSpace(parts[1])
		}
		return hostPart
	}
	if len(parts) == 3 {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(port)
}

// composeConfig represents extracted facts from `docker compose config --format json`.
type composeConfig struct {
	Services map[string]composeService `json:"services"`
}

type composeService struct {
	Image         string              `json:"image"`
	ContainerName string              `json:"container_name"`
	EnvFile       []string            `json:"env_file,omitempty"`
	HealthCheck   *healthCheck        `json:"healthcheck,omitempty"`
	Ports         []string            `json:"ports,omitempty"`
	Volumes       []composeVolume     `json:"volumes,omitempty"`
}

type healthCheck struct {
	Test []string `json:"test,omitempty"`
}

type composeVolume struct {
	Type   string `json:"type,omitempty"`
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
}

// composePSService represents one entry from `docker compose ps --format json`.
type composePSService struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health,omitempty"`
}

func parseComposePS(data []byte) []composePSService {
	var services []composePSService
	if err := json.Unmarshal(data, &services); err == nil {
		return services
	}
	// Fallback: JSONL
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var s composePSService
		if err := json.Unmarshal([]byte(line), &s); err == nil {
			services = append(services, s)
		}
	}
	return services
}
