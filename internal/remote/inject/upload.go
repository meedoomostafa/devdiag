package inject

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/meedoomostafa/devdiag/internal/remote/session"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
	sshtransport "github.com/meedoomostafa/devdiag/internal/remote/transport/ssh"
)

// UploadTarStream uploads a local staging directory to a remote target
// using a streamed tar over ssh. It returns an error if the upload fails.
func UploadTarStream(ctx context.Context, t *target.Target, localDir, remoteDir string, options ...sshtransport.Options) error {
	sshOptions := sshtransport.Options{}
	if len(options) > 0 {
		sshOptions = options[0]
	}

	// Build ssh host argument
	host := t.Host
	if t.User != "" {
		host = fmt.Sprintf("%s@%s", t.User, t.Host)
	}

	// tar -C localDir -cf - . | ssh host -- 'mkdir -p remoteDir && tar -C remoteDir -xf -'
	tarCmd := exec.CommandContext(ctx, "tar", "-C", localDir, "-cf", "-", ".")
	sshArgs := []string{"-o", "ConnectTimeout=10"}
	sshArgs = append(sshArgs, sshOptions.Args()...)
	if t.Port != 0 && t.Port != 22 {
		sshArgs = append(sshArgs, "-p", fmt.Sprintf("%d", t.Port))
	}
	sshArgs = append(sshArgs, host, "--")
	remoteShellDir := session.ShellPath(remoteDir)
	quotedDir := session.ShellQuote(remoteShellDir)
	remoteCommand := fmt.Sprintf("mkdir -p %s && tar -C %s -xf -", quotedDir, quotedDir)
	sshArgs = append(sshArgs, "sh -lc "+session.ShellQuote(remoteCommand))
	sshCmd := exec.CommandContext(ctx, "ssh", sshArgs...)

	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("tar stdout pipe: %w", err)
	}
	sshCmd.Stdin = pipe

	if err := sshCmd.Start(); err != nil {
		return fmt.Errorf("ssh start: %w", err)
	}
	if err := tarCmd.Run(); err != nil {
		return fmt.Errorf("tar run: %w", err)
	}
	if err := sshCmd.Wait(); err != nil {
		return fmt.Errorf("ssh wait: %w", err)
	}
	return nil
}
