package ssh

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

// Transport implements transport.Transport for SSH targets.
type Transport struct {
	Target  *target.Target
	Runner  cmdrunner.CommandRunner
	Options Options
}

// Options carries explicit OpenSSH client options needed for non-default
// identity and known-hosts setups.
type Options struct {
	IdentityFile          string
	UserKnownHostsFile    string
	StrictHostKeyChecking string
}

func (o Options) Args() []string {
	var args []string
	if o.IdentityFile != "" {
		args = append(args, "-i", o.IdentityFile)
	}
	if o.UserKnownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+o.UserKnownHostsFile)
	}
	if o.StrictHostKeyChecking != "" {
		args = append(args, "-o", "StrictHostKeyChecking="+o.StrictHostKeyChecking)
	}
	return args
}

// NewTransport creates an SSH transport for the given target.
// If runner is nil, a real runner is used.
func NewTransport(t *target.Target, runner cmdrunner.CommandRunner) *Transport {
	return NewTransportWithOptions(t, runner, Options{})
}

// NewTransportWithOptions creates an SSH transport with explicit OpenSSH options.
func NewTransportWithOptions(t *target.Target, runner cmdrunner.CommandRunner, options Options) *Transport {
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	return &Transport{Target: t, Runner: runner, Options: options}
}

// Kind returns the transport kind.
func (t *Transport) Kind() string { return "ssh" }

// Close is a no-op for SSH.
func (t *Transport) Close() error { return nil }

// sshArgs builds the base ssh arguments for the target.
func (t *Transport) sshArgs(batchMode bool) []string {
	args := []string{"-o", "ConnectTimeout=5"}
	args = append(args, t.Options.Args()...)
	if batchMode {
		args = append(args, "-o", "BatchMode=yes")
	}
	if t.Target.Port != 0 && t.Target.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", t.Target.Port))
	}
	host := t.Target.Host
	if t.Target.User != "" {
		host = fmt.Sprintf("%s@%s", t.Target.User, t.Target.Host)
	}
	return append(args, host)
}

// Probe checks connectivity and collects remote environment facts.
func (t *Transport) Probe(ctx context.Context) (*transport.RemoteProbeResult, error) {
	res := &transport.RemoteProbeResult{
		Tools: make(map[string]bool),
	}

	// Step 1: basic connectivity probe
	connectArgs := append(t.sshArgs(true), "--", "printf", "ok")
	connectRes := t.Runner.Run(ctx, "ssh", connectArgs...)
	if connectRes.TimedOut {
		res.Error = "connection timed out"
		return res, nil
	}
	if connectRes.ExitCode != 0 {
		res.Error = classifySSHError(connectRes.Stderr, connectRes.ExitCode)
		return res, nil
	}
	res.Reachable = true

	// Step 2: collect remote facts — each command must emit exactly one line.
	factScript := `printf "%s\n" "${SHELL:-}"
uname -s
uname -m
id -u
id -g
pwd
printf "%s\n" "${HOME:-}"
command -v sh 2>/dev/null || echo ""
command -v bash 2>/dev/null || echo ""
command -v zsh 2>/dev/null || echo ""
command -v fish 2>/dev/null || echo ""
command -v tmux 2>/dev/null || echo ""
command -v vim 2>/dev/null || echo ""
command -v nvim 2>/dev/null || echo ""
command -v tar 2>/dev/null || echo ""
test -w "$HOME" && echo home_writable || echo home_not_writable
`
	factCmd := fmt.Sprintf("sh -lc '%s'", factScript)
	factArgs := append(t.sshArgs(true), "--", factCmd)
	factRes := t.Runner.Run(ctx, "ssh", factArgs...)
	if factRes.ExitCode == 0 {
		parseFactOutput(res, factRes.Stdout)
	} else {
		res.Error = fmt.Sprintf("fact probe failed: %s", factRes.Stderr)
	}

	return res, nil
}

// Run executes a remote command via SSH.
func (t *Transport) Run(ctx context.Context, cmd transport.RemoteCommand) (*transport.RemoteCommandResult, error) {
	args := t.sshArgs(false)
	args = append(args, "--")
	if len(cmd.Args) > 1 {
		args = append(args, shellCommand(cmd.Args))
	} else {
		args = append(args, cmd.Args...)
	}

	res := t.Runner.Run(ctx, "ssh", args...)
	return &transport.RemoteCommandResult{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
		TimedOut: res.TimedOut,
	}, nil
}

// Upload copies localDir to remoteDir via scp.
func (t *Transport) Upload(ctx context.Context, localDir, remoteDir string) error {
	host := t.Target.Host
	if t.Target.User != "" {
		host = fmt.Sprintf("%s@%s", t.Target.User, t.Target.Host)
	}
	args := []string{"-r", "-o", "ConnectTimeout=5"}
	args = append(args, t.Options.Args()...)
	if t.Target.Port != 0 && t.Target.Port != 22 {
		args = append(args, "-P", fmt.Sprintf("%d", t.Target.Port))
	}
	args = append(args, localDir, host+":"+remoteDir)

	res := t.Runner.Run(ctx, "scp", args...)
	if res.ExitCode != 0 {
		return fmt.Errorf("scp failed: %s", res.Stderr)
	}
	return nil
}

// OpenShell opens an interactive SSH shell.
func (t *Transport) OpenShell(ctx context.Context, shell string) error {
	args := t.sshArgs(false)
	if shell != "" {
		args = append(args, "--", shell)
	}
	res := t.Runner.Run(ctx, "ssh", args...)
	if res.ExitCode != 0 {
		return fmt.Errorf("shell exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}

// Enter opens an interactive shell on the remote target with the DevDiag profile sourced.
// It allocates a TTY, forwards stdin/stdout/stderr, and returns the shell's exit code.
func (t *Transport) Enter(remoteDir string) error {
	args := []string{"-t", "-o", "ConnectTimeout=10"}
	args = append(args, t.Options.Args()...)
	if t.Target.Port != 0 && t.Target.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", t.Target.Port))
	}
	host := t.Target.Host
	if t.Target.User != "" {
		host = fmt.Sprintf("%s@%s", t.Target.User, t.Target.Host)
	}
	args = append(args, host, "--")

	// Build shell command that sources the profile and execs the user's shell
	shellCmd := fmt.Sprintf(`export DEVDDIR="%s"; . "$DEVDDIR/env.sh"; exec "${SHELL:-sh}"`, session.ShellPath(remoteDir))
	args = append(args, shellCmd)

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func shellCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, session.ShellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func classifySSHError(stderr string, exitCode int) string {
	stderr = strings.ToLower(stderr)
	switch {
	case strings.Contains(stderr, "permission denied"):
		return "ssh permission denied"
	case strings.Contains(stderr, "could not resolve hostname"):
		return "host unreachable"
	case strings.Contains(stderr, "no route to host"):
		return "host unreachable"
	case strings.Contains(stderr, "connection refused"):
		return "connection refused"
	case strings.Contains(stderr, "connection timed out"):
		return "connection timed out"
	case exitCode == 255:
		return "ssh connection error"
	default:
		return fmt.Sprintf("ssh exited %d: %s", exitCode, stderr)
	}
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

	// Map each output line to its field
	fieldNames := []string{
		"shell", "os", "arch", "uid", "gid", "pwd", "home",
		"sh", "bash", "zsh", "fish", "tmux", "vim", "nvim", "tar",
		"home_writable",
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
		case "home_writable":
			res.HomeWritable = line == "home_writable"
		default:
			// Tool availability
			res.Tools[field] = line != "" && !strings.Contains(line, "not found")
		}
	}

	res.HasTar = res.Tools["tar"]

	// Detect restricted shell: if bash/zsh/fish are present but shell is /bin/sh or /bin/rsh
	if res.Shell == "/bin/sh" || res.Shell == "/bin/rsh" || res.Shell == "/usr/bin/rsh" {
		res.RestrictedShell = true
	}
}
