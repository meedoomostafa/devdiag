package composestatus

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks Compose service status, config validity, bind mounts, and stale containers.
type Collector struct {
	Root   string // repo root
	Runner cmdrunner.CommandRunner
}

func (c *Collector) Name() string {
	return "compose_status"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}
	runner := c.Runner
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
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
	configRes := cmdrunner.RunWithOptions(cmdCtx, runner, cmdrunner.RunOptions{Dir: root}, "docker", "compose", "config", "--format", "json")
	cancel()
	if configRes.ExitCode != 0 {
		notes = append(notes, fmt.Sprintf("docker compose config failed: %s", commandFailure(configRes)))
		status := schema.CollectorPartial
		if configRes.NotFound || configRes.TimedOut || configRes.PermissionDenied ||
			strings.Contains(configRes.Stderr, "permission denied") ||
			strings.Contains(configRes.Stderr, "dial unix") ||
			strings.Contains(configRes.Stderr, "docker: 'compose' is not a docker command") {
			status = schema.CollectorUnavailable
		}
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   status,
			Evidence: evidence,
			Notes:    notes,
		}, nil
	}

	var cfg composeConfig
	if err := json.Unmarshal([]byte(configRes.Stdout), &cfg); err != nil {
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
		// Port mappings (handle both string and object formats)
		for _, port := range svc.Ports {
			hostPort := extractHostPortRaw(port)
			if hostPort != "" {
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("compose_service_%s_host_port", svcName),
					Value:  hostPort,
				})
			}
		}
		// Bind mounts (only explicit type=="bind"; empty type may be named volumes)
		for _, vol := range svc.Volumes {
			if vol.Type == "bind" {
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
	psRes := cmdrunner.RunWithOptions(cmdCtx, runner, cmdrunner.RunOptions{Dir: root}, "docker", "compose", "ps", "-a", "--format", "json")
	cancel()
	if psRes.ExitCode == 0 {
		services := parseComposePS([]byte(psRes.Stdout))
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
		notes = append(notes, fmt.Sprintf("docker compose ps failed: %s", commandFailure(psRes)))
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

func commandFailure(res cmdrunner.Result) string {
	if res.Stderr != "" {
		return strings.TrimSpace(res.Stderr)
	}
	if res.Stdout != "" {
		return strings.TrimSpace(res.Stdout)
	}
	if res.TimedOut {
		return "timed out"
	}
	return fmt.Sprintf("exit code %d", res.ExitCode)
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

func extractHostPortRaw(raw json.RawMessage) string {
	// Try string format first: "5432:5432" or "127.0.0.1:8000:8000"
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return extractHostPort(s)
	}
	// Object format: {"published": "5432", "target": 5432}
	var p struct {
		Published string      `json:"published"`
		Target    interface{} `json:"target"`
	}
	if err := json.Unmarshal(raw, &p); err == nil {
		if p.Published != "" {
			return extractHostPort(p.Published)
		}
		// If only target is specified, no host port mapping
		return ""
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
	Image         string            `json:"image"`
	ContainerName string            `json:"container_name"`
	EnvFile       []string          `json:"env_file,omitempty"`
	HealthCheck   *healthCheck      `json:"healthcheck,omitempty"`
	Ports         []json.RawMessage `json:"ports,omitempty"`
	Volumes       []composeVolume   `json:"volumes,omitempty"`
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
