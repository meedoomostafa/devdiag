package systemd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector detects systemd availability and checks relevant services.
type Collector struct {
	RepoExpectsDocker bool // set by caller based on repo signals
}

func (c *Collector) Name() string {
	return "systemd"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	// Check if systemctl exists
	_, err := exec.LookPath("systemctl")
	if err != nil {
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorUnavailable,
			Evidence: []schema.Evidence{{Source: "host_systemd", Value: "unavailable"}},
		}, nil
	}

	// Lightweight systemd availability check
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	out, err := exec.CommandContext(cmdCtx, "systemctl", "is-system-running").Output()
	cancel()
	systemdState := strings.TrimSpace(string(out))
	if err != nil {
		// Distinguish degraded (still running) from offline/missing
		if systemdState == "degraded" {
			evidence = append(evidence, schema.Evidence{Source: "host_systemd", Value: "degraded"})
		} else {
			// systemctl exists but may not work (e.g., in container without systemd)
			return schema.CollectorResult{
				Name:     c.Name(),
				Status:   schema.CollectorUnavailable,
				Evidence: []schema.Evidence{{Source: "host_systemd", Value: "not_running"}},
			}, nil
		}
	} else {
		evidence = append(evidence, schema.Evidence{Source: "host_systemd", Value: systemdState})
	}

	// Docker service check only if repo expects Docker
	if c.RepoExpectsDocker {
		dockerActive := false
		for _, unit := range []string{"docker", "docker.socket"} {
			cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			out, err := exec.CommandContext(cmdCtx, "systemctl", "is-active", unit).Output()
			cancel()
			if err == nil && strings.TrimSpace(string(out)) == "active" {
				dockerActive = true
				evidence = append(evidence, schema.Evidence{
					Source: "host_docker_service",
					Value:  fmt.Sprintf("%s=active", unit),
				})
				break
			}
		}
		if !dockerActive {
			evidence = append(evidence, schema.Evidence{
				Source: "host_docker_service",
				Value:  "inactive",
			})
		}
	} else {
		evidence = append(evidence, schema.Evidence{
			Source: "host_docker_service",
			Value:  "not_applicable",
		})
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}
