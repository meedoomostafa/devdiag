package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks Docker daemon accessibility and collects summary facts.
type Collector struct{}

func (c *Collector) Name() string {
	return "docker"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	// Check binary presence
	path, err := exec.LookPath("docker")
	if err != nil {
		applicable := false
		return schema.CollectorResult{
			Name:       c.Name(),
			Status:     schema.CollectorOK,
			Applicable: &applicable,
			Evidence: []schema.Evidence{
				{Source: "docker_binary", Value: "not_found"},
			},
		}, nil
	}
	evidence = append(evidence, schema.Evidence{Source: "docker_binary", Value: path})

	// Check docker compose plugin presence
	composePlugin := false
	legacyCompose := false
	if _, err := exec.LookPath("docker"); err == nil {
		cmdCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := exec.CommandContext(cmdCtx, "docker", "compose", "version").Run()
		cancel()
		if err == nil {
			composePlugin = true
		} else {
			// Try legacy docker-compose binary
			if _, err := exec.LookPath("docker-compose"); err == nil {
				legacyCompose = true
			}
		}
	}
	if composePlugin {
		evidence = append(evidence, schema.Evidence{Source: "docker_compose_plugin", Value: "available"})
	} else if legacyCompose {
		evidence = append(evidence, schema.Evidence{Source: "docker_compose_plugin", Value: "legacy_docker-compose"})
	} else {
		evidence = append(evidence, schema.Evidence{Source: "docker_compose_plugin", Value: "missing"})
	}

	// docker info --format '{{json .}}' with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	out, err := exec.CommandContext(cmdCtx, "docker", "info", "--format", "{{json .}}").Output()
	cancel()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && len(exitErr.Stderr) > 0 {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "permission denied") || strings.Contains(stderr, "dial unix") {
				evidence = append(evidence, schema.Evidence{
					Source: "docker_socket_permission_denied",
					Value:  "true",
				})
				if p := socketPath(); p != "" {
					evidence = append(evidence, schema.Evidence{
						Source: "docker_socket_path",
						Value:  p,
					})
				}
			}
		}
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorUnavailable,
			Evidence: evidence,
			Notes:    []string{fmt.Sprintf("docker info failed: %v", err)},
		}, nil
	}

	var info dockerInfo
	if err := json.Unmarshal(out, &info); err == nil {
		if info.ServerVersion != "" {
			evidence = append(evidence, schema.Evidence{Source: "docker_server_version", Value: info.ServerVersion})
		}
		if info.Rootless != nil && *info.Rootless {
			evidence = append(evidence, schema.Evidence{Source: "docker_rootless", Value: "true"})
		}
		// Driver status for storage hints
		if info.Driver != "" {
			evidence = append(evidence, schema.Evidence{Source: "docker_storage_driver", Value: info.Driver})
		}
		// Cgroup version
		if info.CgroupVersion != "" {
			evidence = append(evidence, schema.Evidence{Source: "docker_cgroup_version", Value: info.CgroupVersion})
		}
		// Memory limit support
		if info.MemoryLimit {
			evidence = append(evidence, schema.Evidence{Source: "docker_memory_limit", Value: "supported"})
		}
	}

	// docker ps -a --format '{{json .}}' only if daemon accessible, filtered by time
	cmdCtx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	out, err = exec.CommandContext(cmdCtx, "docker", "ps", "-a", "--format", "{{json .}}").Output()
	cancel()
	if err == nil {
		containers := parseDockerPSLines(out)
		for _, ctr := range containers {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("docker_container_%s_status", ctr.Names),
				Value:  ctr.State,
			})
			if ctr.Labels != "" {
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("docker_container_%s_labels", ctr.Names),
					Value:  ctr.Labels,
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

func socketPath() string {
	if p := os.Getenv("DOCKER_HOST"); p != "" {
		return p
	}
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/user/1000/docker.sock"} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dockerInfo represents selected fields from `docker info --format '{{json .}}'`.
type dockerInfo struct {
	ServerVersion string `json:"ServerVersion"`
	Rootless      *bool  `json:"rootless,omitempty"`
	Driver        string `json:"Driver"`
	CgroupVersion string `json:"CgroupVersion"`
	MemoryLimit   bool   `json:"MemoryLimit"`
}

// dockerPSLine represents one line from `docker ps -a --format '{{json .}}'`.
type dockerPSLine struct {
	Names  string `json:"Names"`
	State  string `json:"State"`
	Labels string `json:"Labels"`
}

func parseDockerPSLines(data []byte) []dockerPSLine {
	var results []dockerPSLine
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ctr dockerPSLine
		if err := json.Unmarshal([]byte(line), &ctr); err == nil {
			results = append(results, ctr)
		}
	}
	return results
}
