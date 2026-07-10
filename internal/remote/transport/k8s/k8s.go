package k8s

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/remote/session"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/remote/transport"
)

const factScript = `printf '%s\n' "${SHELL:-}"
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

// Transport implements transport.Transport for Kubernetes pod targets.
type Transport struct {
	Target    *target.Target
	Container string
	Runner    cmdrunner.CommandRunner
}

// NewTransport creates a Kubernetes transport for the given target.
func NewTransport(t *target.Target, container string) *Transport {
	return NewTransportWithRunner(t, container, nil)
}

// NewTransportWithRunner creates a Kubernetes transport with an injected runner.
func NewTransportWithRunner(t *target.Target, container string, runner cmdrunner.CommandRunner) *Transport {
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	if container == "" && t != nil {
		container = t.ContainerName
	}
	return &Transport{Target: t, Container: container, Runner: runner}
}

// Kind returns the transport kind.
func (t *Transport) Kind() string { return "k8s" }

// Close is a no-op for Kubernetes transports.
func (t *Transport) Close() error { return nil }

func (t *Transport) runner() cmdrunner.CommandRunner {
	if t.Runner == nil {
		t.Runner = cmdrunner.NewRealRunner()
	}
	return t.Runner
}

func (t *Transport) kubectlExecArgs(interactive bool, stdin bool, command ...string) []string {
	args := make([]string, 0, 10+len(command))
	if t.Target.Context != "" {
		args = append(args, "--context", t.Target.Context)
	}
	args = append(args, "-n", t.Target.Namespace, "exec")
	if interactive {
		args = append(args, "-it")
	} else if stdin {
		args = append(args, "-i")
	}
	args = append(args, t.Target.Pod)
	if t.Container != "" {
		args = append(args, "-c", t.Container)
	}
	args = append(args, "--")
	args = append(args, command...)
	return args
}

// Probe checks pod reachability and collects remote environment facts.
func (t *Transport) Probe(ctx context.Context) (*transport.RemoteProbeResult, error) {
	res := &transport.RemoteProbeResult{
		Tools: make(map[string]bool),
	}

	connect := t.runner().Run(ctx, "kubectl", t.kubectlExecArgs(false, false, "printf", "ok")...)
	if connect.TimedOut {
		res.Error = "kubectl exec timed out"
		return res, nil
	}
	if connect.NotFound {
		res.Error = "kubectl executable not found"
		return res, nil
	}
	if connect.ExitCode != 0 {
		res.Error = fmt.Sprintf("kubectl exec failed: %s", combinedOutput(connect))
		return res, nil
	}
	if strings.TrimSpace(connect.Stdout) != "ok" {
		res.Error = fmt.Sprintf("kubectl exec returned unexpected probe output: %q", strings.TrimSpace(connect.Stdout))
		return res, nil
	}
	res.Reachable = true

	facts := t.runner().Run(ctx, "kubectl", t.kubectlExecArgs(false, false, "sh", "-lc", factScript)...)
	if facts.ExitCode != 0 {
		res.Error = fmt.Sprintf("fact probe failed: %s", combinedOutput(facts))
		return res, nil
	}
	parseFactOutput(res, facts.Stdout)
	return res, nil
}

// Run executes a command in the Kubernetes pod.
func (t *Transport) Run(ctx context.Context, cmd transport.RemoteCommand) (*transport.RemoteCommandResult, error) {
	res := cmdrunner.RunWithOptions(ctx, t.runner(), cmdrunner.RunOptions{Stdin: cmd.Stdin}, "kubectl", t.kubectlExecArgs(false, len(cmd.Stdin) > 0, cmd.Args...)...)
	return &transport.RemoteCommandResult{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
		TimedOut: res.TimedOut,
	}, nil
}

// uploadTarCapBytes bounds the in-memory tar staging buffer. Session staging
// directories are small (profile scripts + manifest); this is a generous cap.
const uploadTarCapBytes = 256 * 1024 * 1024

// Upload streams localDir into remoteDir using tar over kubectl exec.
func (t *Transport) Upload(ctx context.Context, localDir, remoteDir string) error {
	tar := cmdrunner.RunWithOptions(ctx, t.runner(), cmdrunner.RunOptions{
		Dir:            localDir,
		StdoutCapBytes: uploadTarCapBytes,
	}, "tar", "-cf", "-", ".")
	if tar.ExitCode != 0 {
		return fmt.Errorf("tar stage failed: %s", combinedOutput(tar))
	}
	if tar.StdoutTruncated {
		// A truncated capture is a corrupted archive (the capture buffer also
		// appends a text marker); uploading it would silently lose files.
		return fmt.Errorf("tar stream truncated at %d bytes; staging dir too large to upload", uploadTarCapBytes)
	}

	quotedDir := session.ShellQuote(remoteDir)
	remoteCmd := fmt.Sprintf("mkdir -p %s && tar -C %s -xf -", quotedDir, quotedDir)
	kube := cmdrunner.RunWithOptions(ctx, t.runner(), cmdrunner.RunOptions{Stdin: []byte(tar.Stdout)}, "kubectl", t.kubectlExecArgs(false, true, "sh", "-lc", remoteCmd)...)
	if kube.ExitCode != 0 {
		return fmt.Errorf("kubectl upload failed: %s", combinedOutput(kube))
	}
	return nil
}

// OpenShell opens an interactive shell in the pod.
func (t *Transport) OpenShell(ctx context.Context, shell string) error {
	if shell == "" {
		shell = "sh"
	}
	cmd := exec.CommandContext(ctx, "kubectl", t.kubectlExecArgs(true, false, shell)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Enter opens an interactive shell in the pod with the DevDiag profile sourced.
func (t *Transport) Enter(remoteDir string) error {
	shellCmd := fmt.Sprintf(`export DEVDDIR=%s; . "$DEVDDIR/env.sh"; exec "${SHELL:-sh}"`, session.ShellQuote(remoteDir))
	cmd := exec.Command("kubectl", t.kubectlExecArgs(true, false, "sh", "-lc", shellCmd)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func combinedOutput(res cmdrunner.Result) string {
	stdout := strings.TrimSpace(res.Stdout)
	stderr := strings.TrimSpace(res.Stderr)
	switch {
	case stdout != "" && stderr != "":
		return stdout + "\n" + stderr
	case stdout != "":
		return stdout
	case stderr != "":
		return stderr
	case res.TimedOut:
		return "timed out"
	case res.NotFound:
		return "command not found"
	default:
		return fmt.Sprintf("exit code %d", res.ExitCode)
	}
}

func parseFactOutput(res *transport.RemoteProbeResult, stdout string) {
	lines := strings.Split(stdout, "\n")
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
		switch fieldNames[i] {
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
			res.Tools[fieldNames[i]] = line != "" && !strings.Contains(line, "not found")
		}
	}
	res.HasTar = res.Tools["tar"]
}
