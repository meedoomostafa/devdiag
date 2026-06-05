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

// ValidateIdentifier checks that a string is a safe identifier for use in remote commands.
// It rejects leading dashes, whitespace, control characters, shell metacharacters, and quotes.
func ValidateIdentifier(kind, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", kind)
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s must not start with a dash: %q", kind, value)
	}
	for _, r := range value {
		if r <= 32 || r == 127 {
			return fmt.Errorf("%s contains whitespace or control characters: %q", kind, value)
		}
	}
	if strings.ContainsAny(value, "|&;<>$\\`'\"") {
		return fmt.Errorf("%s contains shell metacharacters or quotes: %q", kind, value)
	}
	return nil
}

// Parse parses a raw target string into a structured Target.
// Invalid forms return an error with exit code semantics (caller maps to code 2).
func Parse(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("target is empty")
	}

	var t *Target
	var err error

	// Container targets: container:<id> or container:docker/<id> or container:podman/<id>
	if strings.HasPrefix(raw, "container:") {
		t, err = parseContainer(raw)
	} else if strings.HasPrefix(raw, "k8s:") {
		// Kubernetes targets: k8s:namespace/pod or k8s:context/namespace/pod
		t, err = parseK8s(raw)
	} else {
		// SSH targets: user@host, user@host:port, host, or ssh://user@host:port
		t, err = parseSSH(raw)
	}

	if err != nil {
		return nil, err
	}

	// Canonicalize Raw to ensure it never contains secrets and has a standard form.
	t.Raw = t.String()
	return t, nil
}

func parseContainer(raw string) (*Target, error) {
	body := strings.TrimPrefix(raw, "container:")
	if body == "" {
		return nil, fmt.Errorf("container target is missing identifier")
	}

	t := &Target{
		Kind: KindContainer,
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

	if err := ValidateIdentifier("container ID", t.Container); err != nil {
		return nil, err
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

	if t.Context != "" {
		if err := ValidateIdentifier("kubernetes context", t.Context); err != nil {
			return nil, err
		}
	}
	if err := ValidateIdentifier("kubernetes namespace", t.Namespace); err != nil {
		return nil, err
	}
	if err := ValidateIdentifier("kubernetes pod", t.Pod); err != nil {
		return nil, err
	}

	return t, nil
}

func parseSSH(raw string) (*Target, error) {
	t := &Target{
		Kind: KindSSH,
		Port: 22,
	}

	// Handle ssh:// URI scheme
	if strings.HasPrefix(raw, "ssh://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid ssh URL: %w", err)
		}
		if u.User != nil {
			if _, set := u.User.Password(); set {
				return nil, fmt.Errorf("ssh URL must not contain a password")
			}
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
	} else {
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
		t.Host = hostPart
	}

	if t.User != "" {
		if err := ValidateIdentifier("ssh user", t.User); err != nil {
			return nil, err
		}
	}
	if err := ValidateIdentifier("ssh host", t.Host); err != nil {
		return nil, err
	}

	return t, nil
}

func SameTarget(a, b Target) bool {
	if a.Kind != b.Kind {
		return false
	}
	// Normalization happens during Parse, so String() is canonical enough for most fields.
	// But we check specific fields to be absolutely sure.
	if a.Kind == KindSSH {
		return a.User == b.User && a.Host == b.Host && a.Port == b.Port
	}
	if a.Kind == KindContainer {
		return a.Runtime == b.Runtime && a.Container == b.Container
	}
	if a.Kind == KindK8s {
		return a.Context == b.Context && a.Namespace == b.Namespace && a.Pod == b.Pod && a.ContainerName == b.ContainerName
	}
	return a.String() == b.String()
}
