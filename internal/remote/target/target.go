package target

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Kind represents the type of remote target.
type Kind string

const (
	KindSSH       Kind = "ssh"
	KindContainer Kind = "container"
	KindK8s       Kind = "k8s"
)

// Target represents a parsed remote target specification.
type Target struct {
	Kind          Kind   `json:"kind"`
	Raw           string `json:"raw"`
	User          string `json:"user,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	Container     string `json:"container,omitempty"`
	Runtime       string `json:"runtime,omitempty"` // docker, podman, auto
	Context       string `json:"context,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	Pod           string `json:"pod,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
}

// String returns a normalized string representation.
func (t Target) String() string {
	switch t.Kind {
	case KindSSH:
		if t.Port != 0 && t.Port != 22 {
			return fmt.Sprintf("%s@%s:%d", t.User, t.Host, t.Port)
		}
		if t.User != "" {
			return fmt.Sprintf("%s@%s", t.User, t.Host)
		}
		return t.Host
	case KindContainer:
		if t.Runtime != "" && t.Runtime != "auto" {
			return fmt.Sprintf("container:%s/%s", t.Runtime, t.Container)
		}
		return fmt.Sprintf("container:%s", t.Container)
	case KindK8s:
		if t.Context != "" {
			return fmt.Sprintf("k8s:%s/%s/%s", t.Context, t.Namespace, t.Pod)
		}
		return fmt.Sprintf("k8s:%s/%s", t.Namespace, t.Pod)
	}
	return t.Raw
}

// Parse parses a raw target string into a structured Target.
// Invalid forms return an error with exit code semantics (caller maps to code 2).
func Parse(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("target is empty")
	}

	// Container targets: container:<id> or container:docker/<id> or container:podman/<id>
	if strings.HasPrefix(raw, "container:") {
		return parseContainer(raw)
	}

	// Kubernetes targets: k8s:namespace/pod or k8s:context/namespace/pod
	if strings.HasPrefix(raw, "k8s:") {
		return parseK8s(raw)
	}

	// SSH targets: user@host, user@host:port, host, or ssh://user@host:port
	return parseSSH(raw)
}

func parseContainer(raw string) (*Target, error) {
	body := strings.TrimPrefix(raw, "container:")
	if body == "" {
		return nil, fmt.Errorf("container target is missing identifier")
	}

	t := &Target{
		Kind: KindContainer,
		Raw:  raw,
	}

	// Check for explicit runtime prefix: docker/ or podman/
	if idx := strings.Index(body, "/"); idx != -1 {
		runtime := body[:idx]
		name := body[idx+1:]
		if name == "" {
			return nil, fmt.Errorf("container target missing name after runtime")
		}
		if runtime != "docker" && runtime != "podman" {
			return nil, fmt.Errorf("unsupported container runtime %q, expected docker or podman", runtime)
		}
		t.Runtime = runtime
		t.Container = name
	} else {
		t.Runtime = "auto"
		t.Container = body
	}

	if strings.ContainsAny(t.Container, "|&;<>$\\") {
		return nil, fmt.Errorf("container name contains shell metacharacters")
	}

	return t, nil
}

func parseK8s(raw string) (*Target, error) {
	body := strings.TrimPrefix(raw, "k8s:")
	if body == "" {
		return nil, fmt.Errorf("kubernetes target is missing identifier")
	}

	parts := strings.Split(body, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("kubernetes target must be k8s:namespace/pod or k8s:context/namespace/pod")
	}

	t := &Target{
		Kind: KindK8s,
		Raw:  raw,
	}

	if len(parts) == 2 {
		t.Namespace = parts[0]
		t.Pod = parts[1]
	} else {
		t.Context = parts[0]
		t.Namespace = parts[1]
		t.Pod = parts[2]
	}

	if t.Namespace == "" || t.Pod == "" {
		return nil, fmt.Errorf("kubernetes target namespace and pod must not be empty")
	}
	if containsShellMetachar(t.Context) || containsShellMetachar(t.Namespace) || containsShellMetachar(t.Pod) {
		return nil, fmt.Errorf("kubernetes target contains shell metacharacters")
	}

	return t, nil
}

func parseSSH(raw string) (*Target, error) {
	t := &Target{
		Kind: KindSSH,
		Raw:  raw,
		Port: 22,
	}

	// Handle ssh:// URI scheme
	if strings.HasPrefix(raw, "ssh://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid ssh URL: %w", err)
		}
		if u.User != nil {
			t.User = u.User.Username()
		}
		t.Host = u.Hostname()
		if u.Port() != "" {
			p, err := strconv.Atoi(u.Port())
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid ssh port %q", u.Port())
			}
			t.Port = p
		}
		if t.Host == "" {
			return nil, fmt.Errorf("ssh target is missing host")
		}
		return t, nil
	}

	// Plain target string: user@host or user@host:port or host
	hostPart := raw

	// Extract user
	if at := strings.LastIndex(raw, "@"); at != -1 {
		t.User = raw[:at]
		hostPart = raw[at+1:]
		if t.User == "" {
			return nil, fmt.Errorf("ssh user is empty before @")
		}
	}

	// Extract port from host
	if colon := strings.LastIndex(hostPart, ":"); colon != -1 {
		// Make sure this isn't an IPv6 literal by checking for brackets
		if !strings.HasPrefix(hostPart, "[") {
			portStr := hostPart[colon+1:]
			p, err := strconv.Atoi(portStr)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", portStr)
			}
			t.Port = p
			hostPart = hostPart[:colon]
		}
	}

	if hostPart == "" {
		return nil, fmt.Errorf("ssh target is missing host")
	}

	// Reject shell metacharacters in host
	if containsShellMetachar(hostPart) {
		return nil, fmt.Errorf("host contains shell metacharacters")
	}

	t.Host = hostPart

	return t, nil
}

func containsShellMetachar(value string) bool {
	return strings.ContainsAny(value, "|&;<>$\\")
}
