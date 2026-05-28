package agent

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
)

type RunRequest struct {
	Command string
	Args    []string
	Dir     string
	Timeout time.Duration
	Redact  Redactor
	Runner  cmdrunner.CommandRunner
	RedactLevel string
}

type RunResult struct {
	SchemaVersion   string    `json:"schema_version"`
	Command         string    `json:"command"`
	Args            []string  `json:"args,omitempty"`
	WorkingDir      string    `json:"working_dir,omitempty"`
	ExitCode        int       `json:"exit_code"`
	DurationMs      int64     `json:"duration_ms"`
	TimedOut        bool      `json:"timed_out"`
	StdoutPreview   string    `json:"stdout_preview,omitempty"`
	StderrPreview   string    `json:"stderr_preview,omitempty"`
	Findings        []Finding `json:"findings,omitempty"`
	RedactionStatus string    `json:"redaction_status"`
}

type SandboxRequest struct {
	Root      string
	PatchPath string
	Keep      bool
	Run       RunRequest
	Redact    Redactor
	Runner    cmdrunner.CommandRunner
	RedactLevel string
}

type SandboxResult struct {
	SchemaVersion   string     `json:"schema_version"`
	SandboxDir      string     `json:"sandbox_dir"`
	Kept            bool       `json:"kept"`
	PatchPath       string     `json:"patch_path"`
	PatchApplied    bool       `json:"patch_applied"`
	PatchExitCode   int        `json:"patch_exit_code,omitempty"`
	PatchStderr     string     `json:"patch_stderr,omitempty"`
	Run             *RunResult `json:"run,omitempty"`
	CleanupStatus   string     `json:"cleanup_status"`
	RedactionStatus string     `json:"redaction_status"`
}

func RunCommand(ctx context.Context, req RunRequest) RunResult {
	redact := req.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}
	runner := req.Runner
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	res := cmdrunner.RunWithOptions(ctx, runner, cmdrunner.RunOptions{Dir: req.Dir}, req.Command, req.Args...)
	stdout := redact(res.Stdout)
	stderr := redact(res.Stderr)
	findings := ClassifyPromptInjection(stdout + "\n" + stderr)
	status := req.RedactLevel
	if status == "" {
		status = "default"
	}
	return RunResult{
		SchemaVersion:   SchemaVersion,
		Command:         req.Command,
		Args:            redactArgs(req.Args, redact),
		WorkingDir:      redact(req.Dir),
		ExitCode:        res.ExitCode,
		DurationMs:      res.Duration.Milliseconds(),
		TimedOut:        res.TimedOut,
		StdoutPreview:   truncate(stdout, 8192),
		StderrPreview:   truncate(stderr, 8192),
		Findings:        findings,
		RedactionStatus: status,
	}
}

func RunSandbox(ctx context.Context, req SandboxRequest) (result SandboxResult, err error) {
	redact := req.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}
	runner := req.Runner
	if runner == nil {
		runner = cmdrunner.NewRealRunner()
	}
	sandboxDir, err := os.MkdirTemp("", "devdiag-agent-sandbox-*")
	if err != nil {
		return SandboxResult{}, err
	}
	status := req.RedactLevel
	if status == "" {
		status = "default"
	}
	result = SandboxResult{
		SchemaVersion:   SchemaVersion,
		SandboxDir:      sandboxDir,
		Kept:            req.Keep,
		PatchPath:       redact(req.PatchPath),
		CleanupStatus:   "pending",
		RedactionStatus: status,
	}
	defer func() {
		if req.Keep {
			result.CleanupStatus = "kept"
			return
		}
		_ = os.RemoveAll(sandboxDir)
		result.CleanupStatus = "removed"
	}()

	if err := copyTree(req.Root, sandboxDir); err != nil {
		return result, err
	}

	patch := cmdrunner.RunWithOptions(ctx, runner, cmdrunner.RunOptions{Dir: sandboxDir}, "git", "apply", req.PatchPath)
	result.PatchExitCode = patch.ExitCode
	result.PatchStderr = truncate(redact(patch.Stderr), 4096)
	if patch.ExitCode != 0 || patch.NotFound || patch.TimedOut {
		result.PatchApplied = false
		return result, nil
	}
	result.PatchApplied = true

	runReq := req.Run
	runReq.Dir = sandboxDir
	runReq.Redact = redact
	runReq.Runner = runner
	runReq.RedactLevel = req.RedactLevel
	runResult := RunCommand(ctx, runReq)
	result.Run = &runResult
	return result, nil
}

func redactArgs(args []string, redact Redactor) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = redact(arg)
	}
	return out
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() && shouldSkipCopyDir(d.Name()) {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			sandboxTarget, ok := sandboxSymlinkTarget(src, dst, path, target, linkTarget)
			if !ok {
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.Symlink(sandboxTarget, target)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, target, info.Mode())
	})
}

func sandboxSymlinkTarget(srcRoot, dstRoot, linkPath, dstLink, linkTarget string) (string, bool) {
	srcRootAbs, err := filepath.Abs(srcRoot)
	if err != nil {
		return "", false
	}
	srcRootAbs = filepath.Clean(srcRootAbs)

	rawTargetAbs := linkTarget
	if !filepath.IsAbs(rawTargetAbs) {
		rawTargetAbs = filepath.Join(filepath.Dir(linkPath), rawTargetAbs)
	}
	rawTargetAbs, err = filepath.Abs(rawTargetAbs)
	if err != nil {
		return "", false
	}
	rawTargetAbs = filepath.Clean(rawTargetAbs)
	if !pathWithinRoot(rawTargetAbs, srcRootAbs) {
		return "", false
	}

	if realTarget, err := filepath.EvalSymlinks(rawTargetAbs); err == nil {
		boundsRoot := srcRootAbs
		if realRoot, err := filepath.EvalSymlinks(srcRootAbs); err == nil {
			boundsRoot = filepath.Clean(realRoot)
		}
		if !pathWithinRoot(filepath.Clean(realTarget), boundsRoot) {
			return "", false
		}
	}

	if !filepath.IsAbs(linkTarget) {
		return linkTarget, true
	}
	targetRel, err := filepath.Rel(srcRootAbs, rawTargetAbs)
	if err != nil {
		return "", false
	}
	dstRootAbs, err := filepath.Abs(dstRoot)
	if err != nil {
		return "", false
	}
	sandboxTarget := filepath.Join(filepath.Clean(dstRootAbs), targetRel)
	rewritten, err := filepath.Rel(filepath.Dir(dstLink), sandboxTarget)
	if err != nil {
		return "", false
	}
	return rewritten, true
}

func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

func shouldSkipCopyDir(name string) bool {
	switch name {
	case ".git", ".devdiag":
		return true
	default:
		return false
	}
}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
