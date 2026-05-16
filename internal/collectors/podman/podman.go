package podman

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks Podman availability and collects rootless/UID evidence.
type Collector struct{}

func (c *Collector) Name() string {
	return "podman"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	// Check binary presence
	path, err := exec.LookPath("podman")
	if err != nil {
		applicable := false
		return schema.CollectorResult{
			Name:       c.Name(),
			Status:     schema.CollectorOK,
			Applicable: &applicable,
			Evidence: []schema.Evidence{
				{Source: "podman_binary", Value: "not_found"},
			},
		}, nil
	}
	evidence = append(evidence, schema.Evidence{Source: "podman_binary", Value: path})

	// podman info --format json with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	out, err := exec.CommandContext(cmdCtx, "podman", "info", "--format", "json").Output()
	cancel()
	if err != nil {
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorUnavailable,
			Evidence: evidence,
			Notes:    []string{fmt.Sprintf("podman info failed: %v", err)},
		}, nil
	}

	var info podmanInfo
	if err := json.Unmarshal(out, &info); err == nil {
		if info.Host.RemoteSocket.Path != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_socket_path",
				Value:  info.Host.RemoteSocket.Path,
			})
		}
		if info.Host.Security.Rootless != nil && *info.Host.Security.Rootless {
			evidence = append(evidence, schema.Evidence{Source: "podman_rootless", Value: "true"})
		}
		if info.Host.Security.UIDMap != nil {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_uid_map",
				Value:  fmt.Sprintf("%d", len(info.Host.Security.UIDMap)),
			})
		}
		if info.Host.Security.GIDMap != nil {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_gid_map",
				Value:  fmt.Sprintf("%d", len(info.Host.Security.GIDMap)),
			})
		}
		if info.Host.CgroupManager != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_cgroup_manager",
				Value:  info.Host.CgroupManager,
			})
		}
		if info.Store.GraphRoot != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_graph_root",
				Value:  info.Store.GraphRoot,
			})
		}
		if info.Store.GraphDriverName != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_graph_driver",
				Value:  info.Store.GraphDriverName,
			})
		}
	}

	// podman ps -a --format json only when daemon accessible
	cmdCtx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	out, err = exec.CommandContext(cmdCtx, "podman", "ps", "-a", "--format", "json").Output()
	cancel()
	if err == nil {
		containers := parsePodmanPS(out)
		for _, ctr := range containers {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("podman_container_%s_status", ctr.Names[0]),
				Value:  ctr.State,
			})
			if len(ctr.Labels) > 0 {
				labelStr := joinLabels(ctr.Labels)
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("podman_container_%s_labels", ctr.Names[0]),
					Value:  labelStr,
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

// podmanInfo represents selected fields from `podman info --format json`.
type podmanInfo struct {
	Host struct {
		RemoteSocket struct {
			Path string `json:"path"`
		} `json:"remoteSocket"`
		Security struct {
			Rootless *bool `json:"rootless,omitempty"`
			UIDMap   []struct {
				ContainerID int `json:"container_id"`
			} `json:"uidmap,omitempty"`
			GIDMap []struct {
				ContainerID int `json:"container_id"`
			} `json:"gidmap,omitempty"`
		} `json:"security"`
		CgroupManager string `json:"cgroupManager"`
	} `json:"host"`
	Store struct {
		GraphRoot       string `json:"graphRoot"`
		GraphDriverName string `json:"graphDriverName"`
	} `json:"store"`
}

// podmanContainer represents one entry from `podman ps -a --format json`.
type podmanContainer struct {
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

func parsePodmanPS(data []byte) []podmanContainer {
	var containers []podmanContainer
	if err := json.Unmarshal(data, &containers); err == nil {
		return containers
	}
	// Fallback: might be JSONL (one object per line)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ctr podmanContainer
		if err := json.Unmarshal([]byte(line), &ctr); err == nil {
			containers = append(containers, ctr)
		}
	}
	return containers
}

func joinLabels(labels map[string]string) string {
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ", ")
}
