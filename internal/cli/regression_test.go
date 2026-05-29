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

	// 2. Setup mock scanner
	oldScan := runFixFreshScan
	t.Cleanup(func() { runFixFreshScan = oldScan })

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

	// 3. Test: fix --fresh --list --profile ai-ml --ci --rule-pack custom.rego
	// Since we want to test internal logic without sub-process, we'll use a direct call
	// but we must be careful about global flags.
	// Actually, the user wants us to strengthen the test.
	// The best way is to use a test that calls the command logic directly if possible,
	// or at least more controlled.

	// We'll reset flags to ensure a clean state
	flagProfile = "ai-ml"
	fixFresh = true
	fixList = true
	fixCI = true
	fixRulePack = "custom.rego"
	flagFormat = "json"

	// We need to be in the right directory for artifact discovery
	os.Chdir(dir)

	// Since runFixList is not exported, we use Execute with args or call it.
	// But Execute might be tricky due to os.Exit or state.
	// Let's use a sub-test that calls runFixList.

	logger := buildLogger()
	err := runFixList(fixCmd, logger, buildColorMode())
	if err != nil {
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
}

func TestFixFresh_PerformsRealScan(t *testing.T) {
	// 1. Create a fake saved report
	dir := t.TempDir()
	writeSavedReport(t, dir, "old-run", schema.Report{
		RunID:    "old-run",
		Findings: []schema.Finding{{ID: "F-STALE", Title: "Stale"}},
	})

	// 2. ResolveReportWithFresh should use app.Scan
	// Since we can't easily mock app.Scan for runBinaryInDir (which runs a sub-process),
	// we'll check the source in the output.

	stdout, stderr, code := runBinaryInDir(dir, "fix", "--fresh", "--list", "--format", "json")
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

func TestRemoteClean_SessionTargetMismatch(t *testing.T) {
	dir := t.TempDir()

	// Actually we need to use internal/remote/session.WriteCache but we can just write the file to the mock cache dir
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)

	// We need to set XDG_CACHE_HOME for the test
	t.Setenv("XDG_CACHE_HOME", dir)

	// Write a fake manifest file
	// filename := fmt.Sprintf("%s_%s.json", manifest.Target.Kind, manifest.SessionID)
	// path := filepath.Join(dir, "devdiag", "remote", "sessions", filename)
	realCacheDir := filepath.Join(dir, "devdiag", "remote", "sessions")
	os.MkdirAll(realCacheDir, 0700)

	manifestData := `{
		"session_id": "session-A",
		"target": {
			"kind": "ssh",
			"raw": "user@host-A",
			"host": "host-A"
		},
		"root_dir": "/tmp/devdiag-remote/session-A",
		"status": "active"
	}`
	os.WriteFile(filepath.Join(realCacheDir, "ssh_session-A.json"), []byte(manifestData), 0600)

	// 2. Try to clean target B with session A
	_, stderr, code := runBinary("remote", "clean", "user@host-B", "--session", "session-A")
	if code != exitcode.InvalidInput.Int() {
		t.Fatalf("expected exit code %d for mismatch, got %d", exitcode.InvalidInput.Int(), code)
	}

	if !strings.Contains(stderr, "does not match target") {
		t.Errorf("expected mismatch error in stderr, got: %s", stderr)
	}
}
