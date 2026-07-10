package inject

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

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
	// Both processes run in their own process group so context cancellation
	// kills the whole pipeline, not just the direct children.
	tarCmd := exec.Command("tar", "-C", localDir, "-cf", "-", ".")
	tarCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("tar stdout pipe: %w", err)
	}
	sshCmd.Stdin = pipe

	if err := sshCmd.Start(); err != nil {
		return fmt.Errorf("ssh start: %w", err)
	}
	if err := tarCmd.Start(); err != nil {
		killGroup(sshCmd)
		_ = sshCmd.Wait()
		return fmt.Errorf("tar start: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		tarErr := tarCmd.Wait()
		sshErr := sshCmd.Wait()
		// Report the ssh error first: when ssh dies (auth/connect failure),
		// tar exits with SIGPIPE, which would mask the root cause.
		if sshErr != nil {
			done <- fmt.Errorf("ssh wait: %w", sshErr)
			return
		}
		if tarErr != nil {
			done <- fmt.Errorf("tar run: %w", tarErr)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		killGroup(tarCmd)
		killGroup(sshCmd)
		<-done
		return fmt.Errorf("upload canceled: %w", ctx.Err())
	}
}

// killGroup terminates a command's process group (SIGTERM, then SIGKILL).
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid := -cmd.Process.Pid
	_ = syscall.Kill(pgid, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(pgid, syscall.SIGKILL)
}
