package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/app"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestFixFresh_Strengthened(t *testing.T) {
	dir := t.TempDir()

	// 1. Create a fake saved report
	writeSavedReport(t, dir, "old-run", schema.Report{
		RunID:    "old-run",
		Findings: []schema.Finding{{ID: "F-STALE", Title: "Stale"}},
	})

	// 2. Setup mock scanner and restore state
	oldScan := runFixFreshScan
	t.Cleanup(func() { runFixFreshScan = oldScan })

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	oldProfile := flagProfile
	oldFixFresh := fixFresh
	oldFixList := fixList
	oldFixCI := fixCI
	oldFixRulePack := fixRulePack
	oldFormat := flagFormat
	t.Cleanup(func() {
		flagProfile = oldProfile
		fixFresh = oldFixFresh
		fixList = oldFixList
		fixCI = oldFixCI
		fixRulePack = oldFixRulePack
		flagFormat = oldFormat
	})

	var capturedOpts app.ScanOptions
	scanCount := 0
	runFixFreshScan = func(ctx context.Context, opts app.ScanOptions, sink app.EventSink) (*schema.Report, error) {
		scanCount++
		capturedOpts = opts
		return &schema.Report{
			RunID: "fresh-run",
			Findings: []schema.Finding{
				{ID: "F-FRESH", Title: "Fresh"},
			},
		}, nil
	}

	// 3. Test internal logic with direct call
	flagProfile = "ai-ml"
	fixFresh = true
	fixList = true
	fixCI = true
	fixRulePack = "custom.rego"
	flagFormat = "json"

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	logger := buildLogger()
	if err := runFixList(fixCmd, logger, buildColorMode()); err != nil {
		t.Fatalf("runFixList failed: %v", err)
	}

	if scanCount != 1 {
		t.Errorf("expected 1 scan, got %d", scanCount)
	}
	if capturedOpts.Profile != "ai-ml" {
		t.Errorf("expected profile ai-ml, got %s", capturedOpts.Profile)
	}
	if !capturedOpts.CI {
		t.Error("expected CI=true")
	}
	if capturedOpts.RulePackPath != "custom.rego" {
		t.Errorf("expected rule pack custom.rego, got %s", capturedOpts.RulePackPath)
	}
	if capturedOpts.RedactLevel != flagRedact {
		t.Errorf("expected redact level %s, got %s", flagRedact, capturedOpts.RedactLevel)
	}
}

func TestFixFresh_PerformsRealScan(t *testing.T) {
	// 1. Create a fake saved report
	dir := t.TempDir()
	writeSavedReport(t, dir, "old-run", schema.Report{
		RunID:    "old-run",
		Findings: []schema.Finding{{ID: "F-STALE", Title: "Stale"}},
	})

	// 2. ResolveReportWithFresh should use app.Scan.
	// Since runBinaryInDir runs a sub-process, we'll check the source in the output.

	stdout, stderr, code := runBinaryInDir(dir, "--debug", "fix", "--fresh", "--list", "--format", "json")
	if code != 0 {
		t.Fatalf("fix --fresh --list exit code = %d, want 0, stderr=%s", code, stderr)
	}

	var proposals []schema.FixProposal
	if err := json.Unmarshal([]byte(stdout), &proposals); err != nil {
		t.Fatal(err)
	}

	// In the real scan, it will scan the temp dir which has no findings.
	if len(proposals) != 0 {
		t.Errorf("expected 0 fresh proposals for empty dir, got %d", len(proposals))
	}

	if !strings.Contains(stderr, "running fresh scan before planning") {
		t.Error("expected log message about fresh scan")
	}
}

func TestFixFresh_StaleFindingNotApplied(t *testing.T) {
	dir := t.TempDir()

	// 1. Saved report has F-STALE
	writeSavedReport(t, dir, "old-run", schema.Report{
		RunID:    "old-run",
		Findings: []schema.Finding{{ID: "F-STALE", Title: "Stale"}},
	})

	// 2. Run fix F-STALE --fresh --apply.
	// The fresh scan will not find F-STALE.
	stdout, _, code := runBinaryInDir(dir, "fix", "F-STALE", "--fresh", "--apply")
	if code != 0 {
		t.Fatalf("expected 0 code for missing finding in fresh scan, got %d", code)
	}

	if !strings.Contains(stdout, "No fix proposals for finding F-STALE") {
		t.Errorf("expected message about no findings, got: %s", stdout)
	}
}

func TestFixFresh_DisappearingFindingDoesNotApply(t *testing.T) {
	dir := t.TempDir()

	// 1. Create a non-executable script
	scriptPath := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho hi\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Saved report has F-AUTO-SAFE pointing to this script
	writeSavedReport(t, dir, "old-run", schema.Report{
		RunID: "old-run",
		Repo:  schema.RepoInfo{Root: dir},
		Findings: []schema.Finding{{
			ID:       "F-AUTO-SAFE",
			Title:    "Safe Finding",
			FixHints: []string{"chmod-script"},
			Evidence: []schema.Evidence{{Source: "host_script_not_executable", Value: "script.sh"}},
		}},
	})

	// 3. Setup mock scanner and restore state
	oldScan := runFixFreshScan
	t.Cleanup(func() { runFixFreshScan = oldScan })

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	oldFixFresh := fixFresh
	oldFixApply := fixApply
	oldFixHint := fixHint
	t.Cleanup(func() {
		fixFresh = oldFixFresh
		fixApply = oldFixApply
		fixHint = oldFixHint
	})

	// Setup mock scanner that returns NO findings
	runFixFreshScan = func(ctx context.Context, opts app.ScanOptions, sink app.EventSink) (*schema.Report, error) {
		return &schema.Report{
			RunID:    "fresh-empty-run",
			Findings: []schema.Finding{},
		}, nil
	}

	// 4. Try to apply F-AUTO-SAFE with --fresh in-process
	fixFresh = true
	fixApply = true
	fixHint = ""

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	logger := buildLogger()
	stdout := &strings.Builder{}
	fixCmd.SetOut(stdout)

	if err := runFix(fixCmd, "F-AUTO-SAFE", logger, buildColorMode()); err != nil {
		t.Fatalf("runFix failed: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "No fix proposals for finding F-AUTO-SAFE") {
		t.Errorf("expected 'No fix proposals' message, got: %s", got)
	}

	// 5. Verify no mutation happened (script should still be 0644, not executable)
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0111 != 0 {
		t.Errorf("script became executable; fallback suspected! perm: %o", info.Mode().Perm())
	}
}

func TestRemoteClean_SessionTargetMismatch(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	realCacheDir := filepath.Join(cacheDir, "devdiag", "remote", "sessions")
	os.MkdirAll(realCacheDir, 0700)

	sessionID := "20260516T203500Z_sessionA"
	// filename format: <kind>_<sessionID>.json
	filename := "ssh_" + sessionID + ".json"
	path := filepath.Join(realCacheDir, filename)
	manifestData := `{
		"schema_version": "0.1",
		"session_id": "` + sessionID + `",
		"target": {
			"kind": "ssh",
			"raw": "user@host-A",
			"host": "host-A",
			"port": 22
		},
		"root_dir": "~/.devdiag/remote/` + sessionID + `",
		"status": "active"
	}`
	if err := os.WriteFile(path, []byte(manifestData), 0600); err != nil {
		t.Fatal(err)
	}

	// Double check file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written: %v", err)
	}

	// 2. Try to clean target B with session A
	env := append(os.Environ(), "XDG_CACHE_HOME="+cacheDir)
	_, stderr, code := runBinaryWithEnv(env, "remote", "clean", "user@host-B", "--session", sessionID)
	if code != exitcode.InvalidInput.Int() {
		t.Fatalf("expected exit code %d for mismatch, got %d. stderr: %s", exitcode.InvalidInput.Int(), code, stderr)
	}

	if !strings.Contains(stderr, "does not match target") {
		t.Errorf("expected mismatch error in stderr, got: %s", stderr)
	}
}
