package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// TestExitCodeContract pins the public CLI exit-code contract end-to-end.
// Every case runs the real binary; codes here are load-bearing for CI users
// and the GitHub Action and must not change casually.
func TestExitCodeContract(t *testing.T) {
	cleanDir := t.TempDir()

	cases := []struct {
		name string
		dir  string
		args []string
		want exitcode.Code
	}{
		{
			name: "clean scan succeeds",
			dir:  cleanDir,
			args: []string{"scan", ".", "--format", "json"},
			want: exitcode.Success,
		},
		{
			name: "findings at threshold exit 1",
			dir:  "", // fixture built per-case below
			args: []string{"scan", ".", "--format", "json", "--fail-severity", "info"},
			want: exitcode.FindingsExist,
		},
		{
			name: "fail-severity off suppresses findings exit",
			dir:  "",
			args: []string{"scan", ".", "--format", "json", "--fail-severity", "off"},
			want: exitcode.Success,
		},
		{
			name: "invalid format flag value",
			dir:  cleanDir,
			args: []string{"scan", ".", "--format", "bogus"},
			want: exitcode.InvalidInput,
		},
		{
			name: "invalid redact flag value",
			dir:  cleanDir,
			args: []string{"scan", ".", "--redact", "bogus"},
			want: exitcode.InvalidInput,
		},
		{
			name: "nonexistent scan path",
			dir:  cleanDir,
			args: []string{"scan", "/nonexistent-devdiag-contract-path"},
			want: exitcode.InvalidInput,
		},
		{
			name: "unknown flag",
			dir:  cleanDir,
			args: []string{"--bogus-flag"},
			want: exitcode.InvalidInput,
		},
		{
			name: "unknown subcommand",
			dir:  cleanDir,
			args: []string{"nosuchcommand"},
			want: exitcode.InvalidInput,
		},
		{
			name: "unknown flag on subcommand",
			dir:  cleanDir,
			args: []string{"scan", ".", "--bogus-flag"},
			want: exitcode.InvalidInput,
		},
		{
			name: "report missing file",
			dir:  cleanDir,
			args: []string{"report", "--report", "/nonexistent-report.json"},
			want: exitcode.InvalidInput,
		},
		{
			name: "help exits success",
			dir:  cleanDir,
			args: []string{"--help"},
			want: exitcode.Success,
		},
		{
			name: "missing flag value",
			dir:  cleanDir,
			args: []string{"scan", ".", "--format"},
			want: exitcode.InvalidInput,
		},
		{
			name: "unknown shorthand flag",
			dir:  cleanDir,
			args: []string{"scan", ".", "-Z"},
			want: exitcode.InvalidInput,
		},
		{
			name: "positional arg count violation",
			dir:  cleanDir,
			args: []string{"agent", "run"},
			want: exitcode.InvalidInput,
		},
	}

	findingsDir := writeFindingsFixture(t)
	for i := range cases {
		if cases[i].dir == "" {
			cases[i].dir = findingsDir
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := runBinaryInDir(tc.dir, tc.args...)
			if code != tc.want.Int() {
				t.Errorf("exit code = %d, want %d (%s); stderr: %s", code, tc.want.Int(), tc.name, stderr)
			}
		})
	}
}

// TestExitCodeContract_TraceMissingBinary accepts either failure code: on
// hosts with a working trace backend the missing binary reaches repro and
// exits 6; when strace/ptrace is unavailable the backend check fires first
// and exits 7. Both are contract-valid; success or other codes are not.
func TestExitCodeContract_TraceMissingBinary(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := runBinaryInDir(dir, "trace", "nosuchbinary-devdiag-contract")
	if code != exitcode.ReproFailed.Int() && code != exitcode.TraceUnavailable.Int() {
		t.Fatalf("trace missing binary exit = %d, want %d or %d; stderr: %s",
			code, exitcode.ReproFailed.Int(), exitcode.TraceUnavailable.Int(), stderr)
	}
}

// writeFindingsFixture creates a repo that deterministically produces at
// least one finding (missing .env keys declared in .env.example).
func writeFindingsFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("API_KEY=\nDB_URL=\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("UNRELATED=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nvmrc"), []byte("18\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExitCodeContract_FixUnknownFindingIsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	writeSavedReport(t, dir, "contract-run", schema.Report{
		SchemaVersion:   schema.SchemaVersion,
		DevDiagVersion:  "test",
		RunID:           "contract-run",
		RedactionStatus: "default",
		Repo:            schema.RepoInfo{Root: dir},
		Collectors:      []schema.CollectorResult{{Name: "env", Status: schema.CollectorOK}},
		Findings:        []schema.Finding{},
	})
	_, stderr, code := runBinaryInDir(dir, "fix", "F-NO-SUCH-FINDING", "--dry-run")
	if code != exitcode.InvalidInput.Int() {
		t.Fatalf("fix unknown finding exit = %d, want %d; stderr: %s", code, exitcode.InvalidInput.Int(), stderr)
	}

	// Documented contract: with --fresh the same miss exits 0, because fresh
	// mode revalidates and a now-absent finding means "nothing to fix".
	stdout, stderr, code := runBinaryInDir(dir, "fix", "F-NO-SUCH-FINDING", "--dry-run", "--fresh")
	if code != exitcode.Success.Int() {
		t.Fatalf("fix --fresh unknown finding exit = %d, want %d; stderr: %s", code, exitcode.Success.Int(), stderr)
	}
	if !strings.Contains(stdout, "No fix proposals") {
		t.Fatalf("fix --fresh unknown finding should report no proposals, got: %s", stdout)
	}
}

func TestExitCodeContract_ScanSaveReportPersistFailure(t *testing.T) {
	dir := t.TempDir()
	// A regular file at .devdiag/runs makes the run-dir creation fail with
	// ENOTDIR regardless of privileges (works under root too, unlike mode
	// bits), while baseline loading still succeeds.
	devdiagDir := filepath.Join(dir, ".devdiag")
	if err := os.Mkdir(devdiagDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(devdiagDir, "runs"), []byte("not a dir"), 0644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runBinaryInDir(dir, "scan", ".", "--save-report", "--format", "json")
	if code != exitcode.InternalError.Int() {
		t.Fatalf("scan --save-report with unwritable .devdiag exit = %d, want %d; stderr: %s", code, exitcode.InternalError.Int(), stderr)
	}
}
