package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/redact"
	"github.com/meedoomostafa/devdiag/internal/remote/inject"
	"github.com/meedoomostafa/devdiag/internal/remote/profile"
	"github.com/meedoomostafa/devdiag/internal/remote/render"
	"github.com/meedoomostafa/devdiag/internal/remote/session"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/remote/transport"
	containertransport "github.com/meedoomostafa/devdiag/internal/remote/transport/container"
	k8stransport "github.com/meedoomostafa/devdiag/internal/remote/transport/k8s"
	sshtransport "github.com/meedoomostafa/devdiag/internal/remote/transport/ssh"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var (
	flagRemoteProfile                  string
	flagRemoteSession                  string
	flagRemoteKeep                     bool
	flagRemoteCleanup                  string
	flagRemoteDryRun                   bool
	flagRemoteAll                      bool
	flagRemoteSSHIdentityFile          string
	flagRemoteSSHKnownHostsFile        string
	flagRemoteSSHStrictHostKeyChecking string
	flagRemoteK8sContainer             string
)

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Remote environment sync for SSH, containers, and Kubernetes",
	Long: `Remote environment sync temporarily injects a safe, minimal developer environment
into SSH hosts, containers, or Kubernetes pods.

By default DevDiag does not overwrite dotfiles, does not require root, and writes
a manifest so every created file can be cleaned up later.`,
}

var remoteDoctorCmd = &cobra.Command{
	Use:   "doctor <target>",
	Short: "Diagnose whether remote sync can work on the target",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteDoctor,
}

var remoteSyncCmd = &cobra.Command{
	Use:   "sync <target>",
	Short: "Inject a remote profile without opening an interactive shell",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteSync,
}

var remoteEnterCmd = &cobra.Command{
	Use:   "enter <target>",
	Short: "Inject a remote profile and open an interactive shell",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteEnter,
}

var remoteCleanCmd = &cobra.Command{
	Use:   "clean <target>",
	Short: "Clean up DevDiag-managed files on the remote target",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteClean,
}

var remoteStatusCmd = &cobra.Command{
	Use:   "status <target>",
	Short: "Show remote sync status for the target",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteStatus,
}

func init() {
	remoteCmd.PersistentFlags().StringVar(&flagRemoteProfile, "profile", "minimal", "Remote profile to inject: minimal")
	remoteCmd.PersistentFlags().StringVar(&flagRemoteSession, "session", "", "Session ID for targeted operations")
	remoteCmd.PersistentFlags().BoolVar(&flagRemoteDryRun, "dry-run", false, "Show planned operations without executing")
	remoteCmd.PersistentFlags().BoolVar(&flagRemoteAll, "all", false, "Clean all sessions for the target")
	remoteCmd.PersistentFlags().StringVar(&flagRemoteSSHIdentityFile, "ssh-identity-file", "", "SSH identity file for remote SSH targets")
	remoteCmd.PersistentFlags().StringVar(&flagRemoteSSHKnownHostsFile, "ssh-known-hosts-file", "", "SSH known_hosts file for remote SSH targets")
	remoteCmd.PersistentFlags().StringVar(&flagRemoteSSHStrictHostKeyChecking, "ssh-strict-host-key-checking", "", "SSH StrictHostKeyChecking value: yes, no, accept-new, ask")
	remoteCmd.PersistentFlags().StringVar(&flagRemoteK8sContainer, "k8s-container", "", "Kubernetes container name for multi-container pods")

	remoteEnterCmd.Flags().BoolVar(&flagRemoteKeep, "keep", false, "Keep remote files after shell exits (enter only)")
	remoteEnterCmd.Flags().StringVar(&flagRemoteCleanup, "cleanup", "always", "Cleanup mode: always, never")

	remoteCmd.AddCommand(remoteDoctorCmd)
	remoteCmd.AddCommand(remoteSyncCmd)
	remoteCmd.AddCommand(remoteEnterCmd)
	remoteCmd.AddCommand(remoteCleanCmd)
	remoteCmd.AddCommand(remoteStatusCmd)
	rootCmd.AddCommand(remoteCmd)
}

func buildRemoteSSHOptions() (sshtransport.Options, error) {
	switch flagRemoteSSHStrictHostKeyChecking {
	case "", "yes", "no", "accept-new", "ask":
	default:
		return sshtransport.Options{}, exitCodeError{code: exitcode.InvalidInput}
	}
	return sshtransport.Options{
		IdentityFile:          flagRemoteSSHIdentityFile,
		UserKnownHostsFile:    flagRemoteSSHKnownHostsFile,
		StrictHostKeyChecking: flagRemoteSSHStrictHostKeyChecking,
	}, nil
}

func applyRemoteK8sOptions(t *target.Target) {
	if t.Kind == target.KindK8s && flagRemoteK8sContainer != "" {
		t.ContainerName = flagRemoteK8sContainer
	}
}

func remoteRootDir(t *target.Target, sessionID string) string {
	switch t.Kind {
	case target.KindContainer:
		return session.ContainerRootDir(sessionID)
	case target.KindK8s:
		return session.K8sRootDir(sessionID)
	default:
		return session.SSHRootDir(sessionID)
	}
}

func runRemoteDoctor(cmd *cobra.Command, args []string) error {
	logger := buildLogger()
	redactEngine := buildRedactEngine()

	t, err := target.Parse(args[0])
	if err != nil {
		return exitCodeError{code: exitcode.InvalidInput}
	}
	applyRemoteK8sOptions(t)

	sshOptions, err := buildRemoteSSHOptions()
	if err != nil {
		return err
	}

	result := render.NewDoctorResult(t)
	result.DevDiagVersion = version.Version
	result.RedactionStatus = string(redactEngine.Level)

	if flagRemoteDryRun {
		result.Profile = flagRemoteProfile
		result.Notes = append(result.Notes, "dry-run: no remote commands executed")
		result.Status = "doctor"
		return outputRemoteResult(result, redactEngine, cmd)
	}

	logger.Info("remote.doctor", fmt.Sprintf("probing %s", t.String()))

	var probeResult *render.Finding
	switch t.Kind {
	case target.KindSSH:
		tr := sshtransport.NewTransportWithOptions(t, nil, sshOptions)
		ctx, cancel := contextWithTimeout(cmd.Context(), 15)
		defer cancel()
		probe, err := tr.Probe(ctx)
		if err != nil {
			return exitCodeError{code: exitcode.InternalError}
		}
		probeResult = buildSSHProbeFindings(result, probe)
	case target.KindContainer:
		tr, err := containertransport.NewTransport(t)
		if err != nil {
			result.Notes = append(result.Notes, err.Error())
			result.Findings = append(result.Findings, render.Finding{
				ID: "F-REMOTE-007", Title: "Target container is not running", Severity: "high", Message: err.Error(),
			})
		} else {
			ctx, cancel := contextWithTimeout(cmd.Context(), 15)
			defer cancel()
			probe, err := tr.Probe(ctx)
			if err != nil {
				return exitCodeError{code: exitcode.InternalError}
			}
			probeResult = buildContainerProbeFindings(result, probe)
		}
	case target.KindK8s:
		tr := k8stransport.NewTransport(t, t.ContainerName)
		ctx, cancel := contextWithTimeout(cmd.Context(), 15)
		defer cancel()
		probe, err := tr.Probe(ctx)
		if err != nil {
			return exitCodeError{code: exitcode.InternalError}
		}
		probeResult = buildK8sProbeFindings(result, probe)
	}

	result.Profile = flagRemoteProfile
	result.Status = "doctor"
	if probeResult != nil {
		result.Findings = append(result.Findings, *probeResult)
	}

	return outputRemoteResultWithFindingExit(result, redactEngine, cmd)
}

func runRemoteSync(cmd *cobra.Command, args []string) error {
	logger := buildLogger()
	redactEngine := buildRedactEngine()

	t, err := target.Parse(args[0])
	if err != nil {
		return exitCodeError{code: exitcode.InvalidInput}
	}
	applyRemoteK8sOptions(t)

	sshOptions, err := buildRemoteSSHOptions()
	if err != nil {
		return err
	}

	// Validate profile
	var p *profile.RemoteProfile
	switch flagRemoteProfile {
	case "minimal":
		p = profile.Minimal()
	default:
		return exitCodeError{code: exitcode.InvalidInput}
	}

	sessionID := session.GenerateID()
	p.SubstituteSessionID(sessionID)

	remoteDir := remoteRootDir(t, sessionID)

	logger.Info("remote.sync", fmt.Sprintf("session=%s target=%s profile=%s", sessionID, t.String(), flagRemoteProfile))

	// Stage profile locally
	stageDir, stagedFiles, err := inject.Stage(p)
	if err != nil {
		return exitCodeError{code: exitcode.InternalError}
	}
	defer os.RemoveAll(stageDir)

	var files []string
	for _, f := range p.Files {
		files = append(files, filepath.Join(remoteDir, f.TargetPath))
	}

	result := render.NewSyncResult(t, flagRemoteProfile, sessionID, remoteDir, files)
	result.DevDiagVersion = version.Version
	result.RedactionStatus = string(redactEngine.Level)

	if flagRemoteDryRun {
		result.Notes = append(result.Notes, "dry-run: no files uploaded")
		return outputRemoteResult(result, redactEngine, cmd)
	}

	// Upload for SSH targets
	manifest := &session.Manifest{
		SchemaVersion:  "0.1",
		DevDiagVersion: version.Version,
		SessionID:      sessionID,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Target:         *t,
		Profile:        flagRemoteProfile,
		Mode:           "temporary",
		RootDir:        remoteDir,
		Status:         "active",
	}
	for _, f := range p.Files {
		manifest.Files = append(manifest.Files, session.ManagedFile{
			Path:    filepath.Join(remoteDir, f.TargetPath),
			Mode:    f.Mode,
			Created: true,
		})
	}

	// Upload based on target kind
	if t.Kind == target.KindSSH {
		ctx, cancel := contextWithTimeout(cmd.Context(), 30)
		defer cancel()
		if err := inject.UploadTarStream(ctx, t, stageDir, remoteDir, sshOptions); err != nil {
			logger.Error("remote.sync", fmt.Sprintf("upload failed: %v", err))
			result.Status = "failed"
			manifest.Status = "failed"
			result.Notes = append(result.Notes, fmt.Sprintf("upload failed: %v", err))
			return outputRemoteResultWithExit(result, redactEngine, cmd, exitcode.ReproFailed)
		}
		result.Notes = append(result.Notes, "upload completed")

		// Write remote manifest
		if err := writeRemoteManifest(ctx, t, manifest, sshOptions); err != nil {
			logger.Warn("remote.sync", fmt.Sprintf("manifest write failed: %v", err))
			result.Notes = append(result.Notes, fmt.Sprintf("manifest write failed: %v", err))
		}
	} else if t.Kind == target.KindContainer || t.Kind == target.KindK8s {
		var tr transport.Transport
		var err error
		transportName := "container"
		if t.Kind == target.KindContainer {
			tr, err = containertransport.NewTransport(t)
		} else {
			transportName = "kubernetes transport"
			tr = k8stransport.NewTransport(t, t.ContainerName)
		}
		if err != nil {
			logger.Error("remote.sync", fmt.Sprintf("%s failed: %v", transportName, err))
			result.Status = "failed"
			manifest.Status = "failed"
			result.Notes = append(result.Notes, fmt.Sprintf("%s failed: %v", transportName, err))
			return outputRemoteResultWithExit(result, redactEngine, cmd, exitcode.ReproFailed)
		}
		ctx, cancel := contextWithTimeout(cmd.Context(), 30)
		defer cancel()
		if err := tr.Upload(ctx, stageDir, remoteDir); err != nil {
			logger.Error("remote.sync", fmt.Sprintf("upload failed: %v", err))
			result.Status = "failed"
			manifest.Status = "failed"
			result.Notes = append(result.Notes, fmt.Sprintf("upload failed: %v", err))
			return outputRemoteResultWithExit(result, redactEngine, cmd, exitcode.ReproFailed)
		}
		result.Notes = append(result.Notes, "upload completed")

		// Write remote manifest via container exec
		data, _ := json.MarshalIndent(manifest, "", "  ")
		res, err := tr.Run(ctx, transport.RemoteCommand{
			Args:  []string{"sh", "-lc", "cat > '" + filepath.Join(remoteDir, "manifest.json") + "'"},
			Stdin: data,
		})
		if err != nil || res.ExitCode != 0 {
			logger.Warn("remote.sync", fmt.Sprintf("manifest write failed: %v", err))
			result.Notes = append(result.Notes, fmt.Sprintf("manifest write failed: %v", err))
		}
	} else {
		result.Notes = append(result.Notes, fmt.Sprintf("upload for %s not yet implemented", t.Kind))
	}

	// Write local session cache
	if err := session.WriteCache(manifest); err != nil {
		logger.Warn("remote.sync", fmt.Sprintf("cache write failed: %v", err))
	}
	_ = stagedFiles
	return outputRemoteResult(result, redactEngine, cmd)
}

func runRemoteEnter(cmd *cobra.Command, args []string) error {
	logger := buildLogger()
	redactEngine := buildRedactEngine()

	t, err := target.Parse(args[0])
	if err != nil {
		return exitCodeError{code: exitcode.InvalidInput}
	}
	applyRemoteK8sOptions(t)

	// Validate cleanup mode
	switch flagRemoteCleanup {
	case "always", "never":
	default:
		logger.Error("remote.enter", fmt.Sprintf("invalid cleanup mode: %s (must be 'always' or 'never')", flagRemoteCleanup))
		return exitCodeError{code: exitcode.InvalidInput}
	}

	sshOptions, err := buildRemoteSSHOptions()
	if err != nil {
		return err
	}

	var p *profile.RemoteProfile
	switch flagRemoteProfile {
	case "minimal":
		p = profile.Minimal()
	default:
		return exitCodeError{code: exitcode.InvalidInput}
	}

	sessionID := session.GenerateID()
	p.SubstituteSessionID(sessionID)

	remoteDir := remoteRootDir(t, sessionID)

	logger.Info("remote.enter", fmt.Sprintf("session=%s target=%s profile=%s", sessionID, t.String(), flagRemoteProfile))

	if flagRemoteDryRun {
		if flagFormat == "json" || flagFormat == "ndjson" || flagFormat == "markdown" || flagFormat == "github" {
			result := render.NewDoctorResult(t)
			result.DevDiagVersion = version.Version
			result.RedactionStatus = string(redactEngine.Level)
			result.Status = "planned"
			result.Profile = flagRemoteProfile
			result.SessionID = sessionID
			result.RemoteDir = remoteDir
			result.CleanupCommand = fmt.Sprintf("devdiag remote clean %s --session %s", t.String(), sessionID)
			result.Notes = append(result.Notes, "dry-run: no files uploaded and no interactive shell opened")
			return outputRemoteResult(result, redactEngine, cmd)
		}
		fmt.Fprintf(os.Stderr, "dry-run: would stage profile, upload to %s, then open interactive shell\n", remoteDir)
		fmt.Fprintf(os.Stderr, "Cleanup:\n  devdiag remote clean %s --session %s\n", t.String(), sessionID)
		return nil
	}

	// Stage and upload profile
	stageDir, _, err := inject.Stage(p)
	if err != nil {
		return exitCodeError{code: exitcode.InternalError}
	}
	defer os.RemoveAll(stageDir)

	manifest := &session.Manifest{
		SchemaVersion: "0.1", DevDiagVersion: version.Version, SessionID: sessionID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Target: *t,
		Profile: flagRemoteProfile, Mode: "temporary", RootDir: remoteDir, Status: "active",
	}
	for _, f := range p.Files {
		manifest.Files = append(manifest.Files, session.ManagedFile{Path: filepath.Join(remoteDir, f.TargetPath), Mode: f.Mode, Created: true})
	}

	// Upload based on target kind
	if t.Kind == target.KindSSH {
		ctx, cancel := contextWithTimeout(cmd.Context(), 30)
		defer cancel()
		if err := inject.UploadTarStream(ctx, t, stageDir, remoteDir, sshOptions); err != nil {
			logger.Error("remote.enter", fmt.Sprintf("upload failed: %v", err))
			return exitCodeError{code: exitcode.ReproFailed}
		}
		if err := writeRemoteManifest(ctx, t, manifest, sshOptions); err != nil {
			logger.Warn("remote.enter", fmt.Sprintf("manifest write failed: %v", err))
		}
	} else if t.Kind == target.KindContainer || t.Kind == target.KindK8s {
		var tr transport.Transport
		var err error
		if t.Kind == target.KindContainer {
			tr, err = containertransport.NewTransport(t)
		} else {
			tr = k8stransport.NewTransport(t, t.ContainerName)
		}
		if err != nil {
			logger.Error("remote.enter", fmt.Sprintf("transport failed: %v", err))
			return exitCodeError{code: exitcode.ReproFailed}
		}
		ctx, cancel := contextWithTimeout(cmd.Context(), 30)
		defer cancel()
		if err := tr.Upload(ctx, stageDir, remoteDir); err != nil {
			logger.Error("remote.enter", fmt.Sprintf("upload failed: %v", err))
			return exitCodeError{code: exitcode.ReproFailed}
		}
		data, _ := json.MarshalIndent(manifest, "", "  ")
		res, err := tr.Run(ctx, transport.RemoteCommand{
			Args:  []string{"sh", "-lc", "cat > '" + filepath.Join(remoteDir, "manifest.json") + "'"},
			Stdin: data,
		})
		if err != nil || res.ExitCode != 0 {
			logger.Warn("remote.enter", fmt.Sprintf("manifest write failed: %v", err))
		}
	} else {
		logger.Info("remote.enter", fmt.Sprintf("upload for %s not yet implemented in enter", t.Kind))
	}
	if err := session.WriteCache(manifest); err != nil {
		logger.Warn("remote.enter", fmt.Sprintf("cache write failed: %v", err))
	}

	// Determine cleanup mode
	cleanupMode := flagRemoteCleanup
	if flagRemoteKeep {
		cleanupMode = "never"
	}

	// Launch interactive shell
	var enterErr error
	var shellExitCode int
	switch t.Kind {
	case target.KindSSH:
		tr := sshtransport.NewTransportWithOptions(t, nil, sshOptions)
		enterErr = tr.Enter(remoteDir)
	case target.KindContainer:
		tr, err := containertransport.NewTransport(t)
		if err != nil {
			enterErr = err
		} else {
			enterErr = tr.Enter(remoteDir)
		}
	case target.KindK8s:
		tr := k8stransport.NewTransport(t, t.ContainerName)
		enterErr = tr.Enter(remoteDir)
	default:
		enterErr = fmt.Errorf("enter not supported for target kind %s", t.Kind)
	}

	if exitErr, ok := enterErr.(*exec.ExitError); ok {
		shellExitCode = exitErr.ExitCode()
	} else if enterErr != nil {
		shellExitCode = 1
	}

	// Cleanup after exit
	needsCleanup := cleanupMode == "always"
	if needsCleanup && shellExitCode == 0 {
		ctx, cancel := contextWithTimeout(context.Background(), 15)
		defer cancel()
		var tr transport.Transport
		if t.Kind == target.KindSSH {
			tr = sshtransport.NewTransportWithOptions(t, nil, sshOptions)
		} else if t.Kind == target.KindContainer {
			tr, _ = containertransport.NewTransport(t)
		} else if t.Kind == target.KindK8s {
			tr = k8stransport.NewTransport(t, t.ContainerName)
		}
		if tr != nil {
			if err := cleanManifest(ctx, tr, manifest); err != nil {
				logger.Warn("remote.enter", fmt.Sprintf("cleanup failed: %v", err))
				fmt.Fprintf(os.Stderr, "\nCleanup failed. Run manually:\n  devdiag remote clean %s --session %s\n", t.String(), sessionID)
				needsCleanup = false
			} else {
				manifest.Status = "cleaned"
				session.WriteCache(manifest)
			}
		}
	}

	if !needsCleanup || enterErr != nil {
		fmt.Fprintf(os.Stderr, "\nCleanup:\n  devdiag remote clean %s --session %s\n", t.String(), sessionID)
	}

	if shellExitCode != 0 {
		return exitCodeError{code: exitcode.ReproFailed}
	}
	return nil
}

func runRemoteClean(cmd *cobra.Command, args []string) error {
	logger := buildLogger()
	redactEngine := buildRedactEngine()

	t, err := target.Parse(args[0])
	if err != nil {
		return exitCodeError{code: exitcode.InvalidInput}
	}
	applyRemoteK8sOptions(t)

	if flagRemoteAll && flagRemoteSession != "" {
		logger.Error("remote.clean", "cannot use --all with --session")
		return exitCodeError{code: exitcode.InvalidInput}
	}

	sshOptions, err := buildRemoteSSHOptions()
	if err != nil {
		return err
	}

	logger.Info("remote.clean", fmt.Sprintf("target=%s session=%s all=%v", t.String(), flagRemoteSession, flagRemoteAll))

	var manifests []*session.Manifest
	if flagRemoteSession != "" {
		cached, err := session.ReadCacheBySessionID(flagRemoteSession)
		if err != nil {
			logger.Error("remote.clean", fmt.Sprintf("session %s not found", flagRemoteSession))
			return exitCodeError{code: exitcode.InvalidInput}
		}
		// Verify target mismatch
		if cached.Target.Kind != t.Kind || cached.Target.Raw != t.Raw || cached.Target.ContainerName != t.ContainerName {
			logger.Error("remote.clean", fmt.Sprintf("session %s does not match target %s", flagRemoteSession, t.String()))
			return exitCodeError{code: exitcode.InvalidInput}
		}
		manifests = append(manifests, cached)
	} else if flagRemoteAll {
		list, err := session.ListCache(string(t.Kind), t.Raw)
		if err != nil {
			logger.Error("remote.clean", fmt.Sprintf("cache read failed: %v", err))
			return exitCodeError{code: exitcode.InternalError}
		}
		manifests = list
	} else {
		cached, err := session.ReadCache(string(t.Kind), t.Raw)
		if err != nil {
			logger.Info("remote.clean", "no cached session found; nothing to clean")
			result := render.NewDoctorResult(t)
			result.DevDiagVersion = version.Version
			result.RedactionStatus = string(redactEngine.Level)
			result.Status = "cleaned"
			result.Notes = append(result.Notes, "no cached session found; nothing to clean")
			return outputRemoteResult(result, redactEngine, cmd)
		}
		manifests = append(manifests, cached)
	}

	if len(manifests) == 0 {
		logger.Info("remote.clean", "no matching sessions found")
		result := render.NewDoctorResult(t)
		result.DevDiagVersion = version.Version
		result.RedactionStatus = string(redactEngine.Level)
		result.Status = "cleaned"
		result.Notes = append(result.Notes, "no matching sessions found")
		return outputRemoteResult(result, redactEngine, cmd)
	}

	if flagRemoteDryRun {
		totalFiles := 0
		for _, m := range manifests {
			totalFiles += len(m.Files)
		}
		result := render.NewDoctorResult(t)
		result.DevDiagVersion = version.Version
		result.RedactionStatus = string(redactEngine.Level)
		result.Status = "cleaned"
		result.Notes = append(result.Notes, fmt.Sprintf("dry-run: would clean %d sessions (total %d files)", len(manifests), totalFiles))
		return outputRemoteResult(result, redactEngine, cmd)
	}

	var tr transport.Transport
	switch t.Kind {
	case target.KindSSH:
		tr = sshtransport.NewTransportWithOptions(t, nil, sshOptions)
	case target.KindContainer:
		tr, err = containertransport.NewTransport(t)
	case target.KindK8s:
		tr = k8stransport.NewTransport(t, t.ContainerName)
	}
	if err != nil {
		logger.Error("remote.clean", fmt.Sprintf("transport failed: %v", err))
		return exitCodeError{code: exitcode.ReproFailed}
	}

	ctx, cancel := contextWithTimeout(context.Background(), 60)
	defer cancel()

	successCount := 0
	failCount := 0
	unsafeCount := 0
	var lastCleanErr error
	for _, m := range manifests {
		if err := cleanManifest(ctx, tr, m); err != nil {
			logger.Warn("remote.clean", fmt.Sprintf("session %s cleanup failed: %v", m.SessionID, err))
			if strings.Contains(err.Error(), "must be within") || strings.Contains(err.Error(), "root dir cannot be") {
				unsafeCount++
			}
			failCount++
			lastCleanErr = err
		} else {
			successCount++
			m.Status = "cleaned"
			_ = session.WriteCache(m)
		}
	}

	result := render.NewDoctorResult(t)
	result.DevDiagVersion = version.Version
	result.RedactionStatus = string(redactEngine.Level)
	result.Status = "cleaned"
	if failCount > 0 {
		if successCount > 0 {
			result.Status = "partial"
		} else if unsafeCount > 0 {
			result.Status = "refused"
		} else {
			result.Status = "failed"
		}
		if unsafeCount > 0 {
			result.Findings = append(result.Findings, render.Finding{
				ID: "F-REMOTE-005", Title: "Unsafe cleanup refused", Severity: "high", Message: lastCleanErr.Error(),
			})
		} else {
			result.Status = "partial"
			result.Findings = append(result.Findings, render.Finding{
				ID: "F-REMOTE-010", Title: "Cleanup completed partially", Severity: "medium", Message: lastCleanErr.Error(),
			})
		}
	}

	if err := outputRemoteResult(result, redactEngine, cmd); err != nil {
		return err
	}

	if failCount > 0 {
		if unsafeCount > 0 && successCount == 0 {
			return exitCodeError{code: exitcode.UnsafeRefused}
		}
		return exitCodeError{code: exitcode.CollectorPartial}
	}

	return nil
}

func runRemoteStatus(cmd *cobra.Command, args []string) error {
	logger := buildLogger()
	redactEngine := buildRedactEngine()

	t, err := target.Parse(args[0])
	if err != nil {
		return exitCodeError{code: exitcode.InvalidInput}
	}
	applyRemoteK8sOptions(t)

	logger.Info("remote.status", fmt.Sprintf("target=%s", t.String()))

	result := render.NewDoctorResult(t)
	result.DevDiagVersion = version.Version
	result.RedactionStatus = string(redactEngine.Level)
	result.Status = "status"

	// Read from local cache
	cached, err := session.ReadCache(string(t.Kind), t.Raw)
	if err != nil {
		result.Notes = append(result.Notes, "no cached session found for target")
	} else {
		result.SessionID = cached.SessionID
		result.RemoteDir = cached.RootDir
		result.Profile = cached.Profile
		result.Status = cached.Status
		result.Notes = append(result.Notes, fmt.Sprintf("cached session: %s", cached.SessionID))
		result.Notes = append(result.Notes, fmt.Sprintf("profile: %s", cached.Profile))
		result.Notes = append(result.Notes, fmt.Sprintf("mode: %s", cached.Mode))
		result.Notes = append(result.Notes, fmt.Sprintf("files managed: %d", len(cached.Files)))
	}

	return outputRemoteResult(result, redactEngine, cmd)
}

// outputRemoteResult renders the result respecting format and redaction.
func outputRemoteResult(result *render.RemoteResult, redactEngine *redact.Engine, cmd *cobra.Command) error {
	// Apply redaction to notes
	for i := range result.Notes {
		result.Notes[i] = redactEngine.RedactString(result.Notes[i], "remote_note")
	}
	for i := range result.Findings {
		result.Findings[i].Message = redactEngine.RedactString(result.Findings[i].Message, "remote_finding")
	}

	if flagFormat == "json" || flagFormat == "ndjson" || flagFormat == "markdown" || flagFormat == "github" {
		return render.Render(result, flagFormat, cmd.OutOrStdout())
	}
	return render.Render(result, "human", cmd.OutOrStdout())
}

func outputRemoteResultWithExit(result *render.RemoteResult, redactEngine *redact.Engine, cmd *cobra.Command, code exitcode.Code) error {
	if err := outputRemoteResult(result, redactEngine, cmd); err != nil {
		return err
	}
	return exitCodeError{code: code}
}

func outputRemoteResultWithFindingExit(result *render.RemoteResult, redactEngine *redact.Engine, cmd *cobra.Command) error {
	if err := outputRemoteResult(result, redactEngine, cmd); err != nil {
		return err
	}
	for _, finding := range result.Findings {
		if finding.Severity == "high" || finding.Severity == "critical" {
			return exitCodeError{code: exitcode.FindingsExist}
		}
	}
	return nil
}

func outputUnsupportedK8s(cmd *cobra.Command, t *target.Target, redactEngine *redact.Engine, operation string) error {
	result := render.NewDoctorResult(t)
	result.DevDiagVersion = version.Version
	result.RedactionStatus = string(redactEngine.Level)
	result.Status = "unsupported"
	result.Profile = flagRemoteProfile
	result.Findings = append(result.Findings, render.Finding{
		ID:       "F-REMOTE-K8S-001",
		Title:    "Kubernetes remote target unsupported",
		Severity: "medium",
		Message:  fmt.Sprintf("remote %s for Kubernetes targets is not implemented yet; target parsing is available, but no kubectl operations are executed", operation),
	})
	result.Notes = append(result.Notes, "kubernetes remote support is planned but not implemented")
	if err := outputRemoteResult(result, redactEngine, cmd); err != nil {
		return err
	}
	return exitCodeError{code: exitcode.InvalidInput}
}

func cleanManifest(ctx context.Context, tr transport.Transport, manifest *session.Manifest) error {
	if err := session.ValidateRootDir(manifest.RootDir, manifest.Target.Kind); err != nil {
		return err
	}
	var lastErr error
	for _, f := range manifest.Files {
		if err := session.ValidateManagedPath(manifest.RootDir, f.Path); err != nil {
			lastErr = err
			continue
		}
		res, err := tr.Run(ctx, transport.RemoteCommand{
			Args: []string{"rm", "-f", f.Path},
		})
		if err != nil {
			lastErr = err
		} else if res.ExitCode != 0 {
			lastErr = fmt.Errorf("rm %s failed: %s", f.Path, res.Stderr)
		}
	}
	// Remove empty directories bottom-up
	rootDir := session.ShellPath(manifest.RootDir)
	res, err := tr.Run(ctx, transport.RemoteCommand{
		Args: []string{"sh", "-lc", "cd " + rootDir + " 2>/dev/null && rmdir $(find . -type d -empty | sort -r) 2>/dev/null || true"},
	})
	if err != nil {
		lastErr = err
	} else if res.ExitCode != 0 {
		// Non-zero is fine for rmdir on non-empty dirs
	}
	return lastErr
}

func writeRemoteManifest(ctx context.Context, t *target.Target, manifest *session.Manifest, sshOptions sshtransport.Options) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tr := sshtransport.NewTransportWithOptions(t, nil, sshOptions)
	remotePath := session.ShellPath(filepath.Join(manifest.RootDir, "manifest.json"))
	// Write manifest using cat over ssh
	res, err := tr.Run(ctx, transport.RemoteCommand{
		Args:  []string{"sh", "-lc", "cat > " + remotePath},
		Stdin: data,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("remote manifest write failed: %s", res.Stderr)
	}
	return nil
}

func contextWithTimeout(parent context.Context, seconds time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, seconds*time.Second)
}

func buildSSHProbeFindings(result *render.RemoteResult, probe *transport.RemoteProbeResult) *render.Finding {
	if !probe.Reachable {
		return &render.Finding{
			ID:       "F-REMOTE-001",
			Title:    "Remote target unreachable",
			Severity: "high",
			Message:  probe.Error,
		}
	}
	if !probe.HomeWritable {
		return &render.Finding{
			ID:       "F-REMOTE-002",
			Title:    "Remote home directory not writable",
			Severity: "high",
			Message:  fmt.Sprintf("home=%s is not writable; remote sync cannot inject profile", probe.Home),
		}
	}
	if probe.Shell == "" {
		return &render.Finding{
			ID:       "F-REMOTE-003",
			Title:    "No supported remote shell found",
			Severity: "high",
			Message:  "no supported shell detected on remote target",
		}
	}
	if !probe.HasTar {
		return &render.Finding{
			ID:       "F-REMOTE-004",
			Title:    "Required upload method unavailable",
			Severity: "medium",
			Message:  "tar not available on remote; upload will use fallback methods",
		}
	}
	return nil
}

func buildContainerProbeFindings(result *render.RemoteResult, probe *transport.RemoteProbeResult) *render.Finding {
	if !probe.Reachable {
		return &render.Finding{
			ID:       "F-REMOTE-007",
			Title:    "Target container is not running",
			Severity: "high",
			Message:  probe.Error,
		}
	}
	if !probe.HomeWritable {
		return &render.Finding{
			ID:       "F-REMOTE-006",
			Title:    "Remote filesystem is read-only",
			Severity: "high",
			Message:  "container filesystem appears read-only; temporary remote sync cannot inject profile",
		}
	}
	// Shell detection: $SHELL may be unset in minimal containers; fall back to Tools map.
	hasShell := probe.Shell != "" || probe.Tools["sh"] || probe.Tools["bash"] || probe.Tools["zsh"] || probe.Tools["fish"]
	if !hasShell {
		return &render.Finding{
			ID:       "F-REMOTE-003",
			Title:    "No supported remote shell found",
			Severity: "high",
			Message:  "no supported shell detected in container",
		}
	}
	if !probe.HasTar {
		return &render.Finding{
			ID:       "F-REMOTE-004",
			Title:    "Required upload method unavailable",
			Severity: "medium",
			Message:  "tar not available in container; upload will use fallback methods",
		}
	}
	return nil
}

func buildK8sProbeFindings(result *render.RemoteResult, probe *transport.RemoteProbeResult) *render.Finding {
	if !probe.Reachable {
		return &render.Finding{
			ID:       "F-REMOTE-K8S-002",
			Title:    "Kubernetes pod unreachable",
			Severity: "high",
			Message:  probe.Error,
		}
	}
	if !probe.HomeWritable {
		return &render.Finding{
			ID:       "F-REMOTE-K8S-003",
			Title:    "Kubernetes pod filesystem is read-only",
			Severity: "high",
			Message:  "pod /tmp is not writable; temporary remote sync cannot inject profile",
		}
	}
	hasShell := probe.Shell != "" || probe.Tools["sh"] || probe.Tools["bash"] || probe.Tools["zsh"] || probe.Tools["fish"]
	if !hasShell {
		return &render.Finding{
			ID:       "F-REMOTE-003",
			Title:    "No supported remote shell found",
			Severity: "high",
			Message:  "no supported shell detected in Kubernetes pod",
		}
	}
	if !probe.HasTar {
		return &render.Finding{
			ID:       "F-REMOTE-004",
			Title:    "Required upload method unavailable",
			Severity: "medium",
			Message:  "tar not available in Kubernetes pod; upload cannot stream profile archive",
		}
	}
	return nil
}
