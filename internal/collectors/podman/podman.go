package podman

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks Podman availability and collects rootless/UID evidence.
type Collector struct {
	Runner cmdrunner.CommandRunner
}

func (c *Collector) Name() string {
	return "podman"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	runner := c.Runner
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	evidence := []schema.Evidence{}

	// Check binary presence
	cmdCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	versionRes := runner.Run(cmdCtx, "podman", "--version")
	cancel()
	if versionRes.NotFound {
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
	evidence = append(evidence, schema.Evidence{Source: "podman_binary", Value: "present"})

	// podman info --format json with timeout
	cmdCtx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	infoRes := runner.Run(cmdCtx, "podman", "info", "--format", "json")
	cancel()
	if infoRes.ExitCode != 0 {
		if podmanRuntimeDirFailure(infoRes) {
			evidence = append(evidence, schema.Evidence{Source: "podman_runtime_dir_error", Value: "true"})
		}
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorUnavailable,
			Evidence: evidence,
			Notes:    []string{fmt.Sprintf("podman info failed: %s", commandFailure(infoRes))},
		}, nil
	}

	var info podmanInfo
	if err := json.Unmarshal([]byte(infoRes.Stdout), &info); err == nil {
		if info.Host.RemoteSocket.Path != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_socket_path",
				Value:  info.Host.RemoteSocket.Path,
			})
		}
		if info.Host.Security.Rootless != nil && *info.Host.Security.Rootless {
			evidence = append(evidence, schema.Evidence{Source: "podman_rootless", Value: "true"})
		}
		if info.Host.NetworkBackend != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_network_backend",
				Value:  info.Host.NetworkBackend,
			})
		}
		if info.Host.RootlessNetworkCmd != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_rootless_network_cmd",
				Value:  info.Host.RootlessNetworkCmd,
			})
		}
		if info.Host.Pasta.Executable != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_pasta_executable",
				Value:  info.Host.Pasta.Executable,
			})
		}
		if info.Host.Slirp4netns.Executable != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_slirp4netns_executable",
				Value:  info.Host.Slirp4netns.Executable,
			})
		}
		uidMapCount := len(info.Host.IDMappings.UIDMap)
		if uidMapCount == 0 {
			uidMapCount = len(info.Host.Security.UIDMap)
		}
		if uidMapCount > 0 {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_uid_map",
				Value:  fmt.Sprintf("%d", uidMapCount),
			})
		}
		gidMapCount := len(info.Host.IDMappings.GIDMap)
		if gidMapCount == 0 {
			gidMapCount = len(info.Host.Security.GIDMap)
		}
		if gidMapCount > 0 {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_gid_map",
				Value:  fmt.Sprintf("%d", gidMapCount),
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
		if info.Store.RunRoot != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "podman_run_root",
				Value:  info.Store.RunRoot,
			})
		}
	}

	// podman ps -a --format json only when daemon accessible
	cmdCtx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	psRes := runner.Run(cmdCtx, "podman", "ps", "-a", "--format", "json")
	cancel()
	if psRes.ExitCode == 0 {
		containers := parsePodmanPS([]byte(psRes.Stdout))
		for _, ctr := range containers {
			name := "unknown"
			if len(ctr.Names) > 0 {
				name = ctr.Names[0]
			}
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("podman_container_%s_status", name),
				Value:  ctr.State,
			})
			if len(ctr.Labels) > 0 {
				labelStr := joinLabels(ctr.Labels)
				evidence = append(evidence, schema.Evidence{
					Source: fmt.Sprintf("podman_container_%s_labels", name),
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

func podmanRuntimeDirFailure(res cmdrunner.Result) bool {
	text := strings.ToLower(res.Stderr + "\n" + res.Stdout)
	return strings.Contains(text, "/run/user") ||
		strings.Contains(text, "xdg_runtime_dir") ||
		strings.Contains(text, "runtime dir") ||
		strings.Contains(text, "runtime directory") ||
		strings.Contains(text, "libpod")
}

// podmanInfo represents selected fields from `podman info --format json`.
type podmanInfo struct {
	Host struct {
		RemoteSocket struct {
			Path string `json:"path"`
		} `json:"remoteSocket"`
		NetworkBackend     string `json:"networkBackend"`
		RootlessNetworkCmd string `json:"rootlessNetworkCmd"`
		IDMappings         struct {
			UIDMap []struct {
				ContainerID int `json:"container_id"`
			} `json:"uidmap,omitempty"`
			GIDMap []struct {
				ContainerID int `json:"container_id"`
			} `json:"gidmap,omitempty"`
		} `json:"idMappings"`
		Security struct {
			Rootless *bool `json:"rootless,omitempty"`
			UIDMap   []struct {
				ContainerID int `json:"container_id"`
			} `json:"uidmap,omitempty"`
			GIDMap []struct {
				ContainerID int `json:"container_id"`
			} `json:"gidmap,omitempty"`
		} `json:"security"`
		Pasta struct {
			Executable string `json:"executable"`
		} `json:"pasta"`
		Slirp4netns struct {
			Executable string `json:"executable"`
		} `json:"slirp4netns"`
		CgroupManager string `json:"cgroupManager"`
	} `json:"host"`
	Store struct {
		GraphRoot       string `json:"graphRoot"`
		RunRoot         string `json:"runRoot"`
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
