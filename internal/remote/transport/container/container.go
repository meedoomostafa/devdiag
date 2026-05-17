package container

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/remote/transport"
)

// Transport implements transport.Transport for container targets.
type Transport struct {
	Target  *target.Target
	Runtime string // "docker" or "podman"
}

// NewTransport creates a container transport, detecting the runtime if needed.
func NewTransport(t *target.Target) (*Transport, error) {
	rt := t.Runtime
	if rt == "" || rt == "auto" {
		var err error
		rt, err = detectRuntime(t.Container)
		if err != nil {
			return nil, err
		}
	}
	return &Transport{Target: t, Runtime: rt}, nil
}

// Kind returns the transport kind.
func (t *Transport) Kind() string { return "container" }

// Close is a no-op for containers.
func (t *Transport) Close() error { return nil }

func (t *Transport) execCmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, t.Runtime, append([]string{"exec"}, args...)...)
}

// Probe checks container state and collects environment facts.
func (t *Transport) Probe(ctx context.Context) (*transport.RemoteProbeResult, error) {
	res := &transport.RemoteProbeResult{
		Tools: make(map[string]bool),
	}

	// Check if container exists and is running
	inspect := exec.CommandContext(ctx, t.Runtime, "inspect", "--format", "{{.State.Running}}", t.Target.Container)
	out, err := inspect.CombinedOutput()
	if err != nil {
		res.Error = fmt.Sprintf("container not found or not running: %s", string(out))
		return res, nil
	}
	if strings.TrimSpace(string(out)) != "true" {
		res.Error = "container is not running"
		return res, nil
	}
	res.Reachable = true

	// Collect remote facts — each command must emit exactly one line.
	factScript := `printf '%s\n' "${SHELL:-}"
uname -s 2>/dev/null || echo unknown
uname -m 2>/dev/null || echo unknown
id -u 2>/dev/null || echo unknown
id -g 2>/dev/null || echo unknown
pwd
printf '%s\n' "${HOME:-}"
command -v sh 2>/dev/null || echo ""
command -v bash 2>/dev/null || echo ""
command -v zsh 2>/dev/null || echo ""
command -v fish 2>/dev/null || echo ""
command -v tmux 2>/dev/null || echo ""
command -v vim 2>/dev/null || echo ""
command -v nvim 2>/dev/null || echo ""
command -v tar 2>/dev/null || echo ""
test -w /tmp 2>/dev/null && echo tmp_writable || echo tmp_not_writable
`
	execCmd := exec.CommandContext(ctx, t.Runtime, "exec", "-i", t.Target.Container, "sh", "-lc", factScript)
	out, err = execCmd.CombinedOutput()
	if err != nil {
		res.Error = fmt.Sprintf("fact probe failed: %s", string(out))
		return res, nil
	}
	parseFactOutput(res, string(out))
	return res, nil
}

// Run executes a command inside the container.
func (t *Transport) Run(ctx context.Context, cmd transport.RemoteCommand) (*transport.RemoteCommandResult, error) {
	args := []string{"exec", "-i", t.Target.Container}
	if cmd.Args != nil {
		args = append(args, cmd.Args...)
	}
	c := exec.CommandContext(ctx, t.Runtime, args...)
	if cmd.Stdin != nil {
		c.Stdin = strings.NewReader(string(cmd.Stdin))
	}
	out, err := c.CombinedOutput()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		exitCode = -1
	}
	return &transport.RemoteCommandResult{
		Stdout:   string(out),
		Stderr:   "",
		ExitCode: exitCode,
	}, nil
}

// Upload copies files into the container.
func (t *Transport) Upload(ctx context.Context, localDir, remoteDir string) error {
	// Create remote directory
	mkdir := exec.CommandContext(ctx, t.Runtime, "exec", t.Target.Container, "mkdir", "-p", remoteDir)
	if out, err := mkdir.CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir remote dir: %s", string(out))
	}

	// Use docker cp / podman cp — copy contents of localDir into remoteDir
	cp := exec.CommandContext(ctx, t.Runtime, "cp", localDir+"/.", t.Target.Container+":"+remoteDir)
	if out, err := cp.CombinedOutput(); err != nil {
		return fmt.Errorf("cp failed: %s", string(out))
	}
	return nil
}

// OpenShell opens an interactive shell inside the container.
func (t *Transport) OpenShell(ctx context.Context, shell string) error {
	args := []string{"exec", "-it", t.Target.Container}
	if shell != "" {
		args = append(args, shell)
	} else {
		args = append(args, "sh")
	}
	cmd := exec.CommandContext(ctx, t.Runtime, args...)
	cmd.Stdin = nil // let stdin be inherited for interactive
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

// Enter opens an interactive shell inside the container with the DevDiag profile sourced.
// It allocates a TTY (-it) and forwards stdin/stdout/stderr.
func (t *Transport) Enter(remoteDir string) error {
	shellCmd := fmt.Sprintf(`export DEVDDIR="%s"; . "$DEVDDIR/env.sh"; exec "${SHELL:-sh}"`, remoteDir)
	cmd := exec.Command(t.Runtime, "exec", "-it", t.Target.Container, "sh", "-lc", shellCmd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func detectRuntime(container string) (string, error) {
	// Try docker first
	if hasContainer("docker", container) {
		return "docker", nil
	}
	// Then podman
	if hasContainer("podman", container) {
		return "podman", nil
	}
	return "", fmt.Errorf("container %q not found with docker or podman", container)
}

func hasContainer(runtime, container string) bool {
	cmd := exec.Command(runtime, "inspect", "--format", "{{.Id}}", container)
	out, err := cmd.CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func parseFactOutput(res *transport.RemoteProbeResult, stdout string) {
	lines := strings.Split(stdout, "\n")
	if len(lines) < 1 {
		return
	}
	// Remove only the final empty line from trailing newline, not leading empty lines.
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	fieldNames := []string{
		"shell", "os", "arch", "uid", "gid", "pwd", "home",
		"sh", "bash", "zsh", "fish", "tmux", "vim", "nvim", "tar",
		"tmp_writable",
	}

	for i, line := range lines {
		if i >= len(fieldNames) {
			break
		}
		line = strings.TrimSpace(line)
		field := fieldNames[i]
		switch field {
		case "shell":
			res.Shell = line
		case "os":
			res.OS = line
		case "arch":
			res.Arch = line
		case "uid":
			res.UID = line
		case "gid":
			res.GID = line
		case "pwd":
			res.PWD = line
		case "home":
			res.Home = line
		case "tmp_writable":
			res.HomeWritable = line == "tmp_writable"
		default:
			res.Tools[field] = line != "" && !strings.Contains(line, "not found")
		}
	}

	res.HasTar = res.Tools["tar"]
}
