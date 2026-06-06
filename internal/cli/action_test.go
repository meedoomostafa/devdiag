package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionScript validates action.sh logic under various conditions.
func TestActionScript(t *testing.T) {
	// Find action.sh absolute path
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Action script is at /scripts/action.sh relative to project root
	// internal/cli is two levels down from root
	actionScript := filepath.Clean(filepath.Join(cwd, "..", "..", "scripts", "action.sh"))
	if _, err := os.Stat(actionScript); err != nil {
		t.Fatalf("action.sh not found at %s: %v", actionScript, err)
	}

	tests := []struct {
		name         string
		env          map[string]string
		mockExitCode string
		wantExitCode int
		verify       func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string)
	}{
		{
			name: "default scan with save-report successfully extracts report",
			env: map[string]string{
				"CI":               "true",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "true",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "high",
				"FORMAT":           "github",
				"REDACT":           "default",
			},
			mockExitCode: "0",
			wantExitCode: 0,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				// Verify report is copied
				reportFile := filepath.Join(tmpDir, "temp-runner", "devdiag-artifacts", "devdiag-report.json")
				if _, err := os.Stat(reportFile); os.IsNotExist(err) {
					t.Fatalf("expected copied report file to exist at %s, but it does not", reportFile)
				}

				// Verify GITHUB_OUTPUT contents
				ghOutput := readGHFile(t, filepath.Join(tmpDir, "gh-output"))
				if ghOutput["report-path"] != reportFile {
					t.Errorf("expected report-path=%s, got %s", reportFile, ghOutput["report-path"])
				}
				if ghOutput["report-uploaded"] != "true" {
					t.Errorf("expected report-uploaded=true, got %s", ghOutput["report-uploaded"])
				}
				if ghOutput["scan-exit-code"] != "0" {
					t.Errorf("expected scan-exit-code=0, got %s", ghOutput["scan-exit-code"])
				}

				// Verify devdiag args
				args := readMockArgs(t, tmpDir)
				if !contains(args, "--save-report") {
					t.Errorf("expected mock devdiag to be called with --save-report, args: %v", args)
				}
				if !contains(args, "--ci") {
					t.Errorf("expected mock devdiag to be called with --ci, args: %v", args)
				}
			},
		},
		{
			name: "save-report=false does not include flag and sets empty path",
			env: map[string]string{
				"CI":               "true",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "true",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "false",
				"FAIL_SEVERITY":    "high",
				"FORMAT":           "github",
				"REDACT":           "default",
			},
			mockExitCode: "0",
			wantExitCode: 0,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				// Verify report is NOT copied
				reportFile := filepath.Join(tmpDir, "temp-runner", "devdiag-artifacts", "devdiag-report.json")
				if _, err := os.Stat(reportFile); err == nil {
					t.Fatalf("expected report file NOT to be copied, but it exists")
				}

				// Verify GITHUB_OUTPUT contents
				ghOutput := readGHFile(t, filepath.Join(tmpDir, "gh-output"))
				if ghOutput["report-path"] != "" {
					t.Errorf("expected empty report-path, got %s", ghOutput["report-path"])
				}
				if ghOutput["report-uploaded"] != "false" {
					t.Errorf("expected report-uploaded=false, got %s", ghOutput["report-uploaded"])
				}

				// Verify devdiag args
				args := readMockArgs(t, tmpDir)
				if contains(args, "--save-report") {
					t.Errorf("expected mock devdiag NOT to be called with --save-report, args: %v", args)
				}
			},
		},
		{
			name: "fail-on-findings=false suppresses exit code 1",
			env: map[string]string{
				"CI":               "true",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "false",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "high",
				"FORMAT":           "github",
				"REDACT":           "default",
			},
			mockExitCode: "1",
			wantExitCode: 0,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				ghOutput := readGHFile(t, filepath.Join(tmpDir, "gh-output"))
				if ghOutput["scan-exit-code"] != "1" {
					t.Errorf("expected scan-exit-code=1, got %s", ghOutput["scan-exit-code"])
				}
				args := readMockArgs(t, tmpDir)
				if !contains(args, "--fail-severity") || getArgValue(args, "--fail-severity") != "off" {
					t.Errorf("expected fail-on-findings=false to map effective fail-severity to off, args: %v", args)
				}
			},
		},
		{
			name: "other exit codes are not suppressed by fail-on-findings=false",
			env: map[string]string{
				"CI":               "true",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "false",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "high",
				"FORMAT":           "github",
				"REDACT":           "default",
			},
			mockExitCode: "3", // collector partial failure
			wantExitCode: 3,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				ghOutput := readGHFile(t, filepath.Join(tmpDir, "gh-output"))
				if ghOutput["scan-exit-code"] != "3" {
					t.Errorf("expected scan-exit-code=3, got %s", ghOutput["scan-exit-code"])
				}
			},
		},
		{
			name: "invalid boolean input causes exit 2",
			env: map[string]string{
				"CI":               "invalid-bool",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "true",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "high",
				"FORMAT":           "github",
				"REDACT":           "default",
			},
			mockExitCode: "0",
			wantExitCode: 2,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				if !strings.Contains(stdout, "ci input must be true or false") && !strings.Contains(stderr, "ci input must be true or false") {
					t.Errorf("expected boolean validation error message, got stdout=%q, stderr=%q", stdout, stderr)
				}
			},
		},
		{
			name: "invalid fail-severity causes exit 2",
			env: map[string]string{
				"CI":               "true",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "true",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "invalid-severity",
				"FORMAT":           "github",
				"REDACT":           "default",
			},
			mockExitCode: "0",
			wantExitCode: 2,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				if !strings.Contains(stdout, "fail-severity input must be one of") && !strings.Contains(stderr, "fail-severity input must be one of") {
					t.Errorf("expected severity validation error message, got stdout=%q, stderr=%q", stdout, stderr)
				}
			},
		},
		{
			name: "mask-values emits GHA mask command",
			env: map[string]string{
				"CI":               "true",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "true",
				"INCLUDE_HIDDEN":   "false",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "high",
				"FORMAT":           "github",
				"REDACT":           "default",
				"MASK_VALUES":      "secret123\nanother_secret",
			},
			mockExitCode: "0",
			wantExitCode: 0,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				if !strings.Contains(stdout, "::add-mask::secret123") {
					t.Errorf("expected ::add-mask::secret123 in stdout, got %q", stdout)
				}
				if !strings.Contains(stdout, "::add-mask::another_secret") {
					t.Errorf("expected ::add-mask::another_secret in stdout, got %q", stdout)
				}
			},
		},
		{
			name: "flag propagation options",
			env: map[string]string{
				"CI":               "false",
				"SUMMARY":          "true",
				"FAIL_ON_FINDINGS": "true",
				"INCLUDE_HIDDEN":   "true",
				"SAVE_REPORT":      "true",
				"FAIL_SEVERITY":    "medium",
				"FORMAT":           "markdown",
				"REDACT":           "strict",
				"PROFILE":          "ai-ml",
				"RULE_PACK":        "packs.yaml",
			},
			mockExitCode: "0",
			wantExitCode: 0,
			verify: func(t *testing.T, tmpDir string, env map[string]string, stdout string, stderr string) {
				args := readMockArgs(t, tmpDir)
				if contains(args, "--ci") {
					t.Errorf("expected --ci NOT to be passed, args: %v", args)
				}
				if !contains(args, "--include-hidden") {
					t.Errorf("expected --include-hidden to be passed, args: %v", args)
				}
				if getArgValue(args, "--profile") != "ai-ml" {
					t.Errorf("expected --profile ai-ml, got %s", getArgValue(args, "--profile"))
				}
				if getArgValue(args, "--rule-pack") != "packs.yaml" {
					t.Errorf("expected --rule-pack packs.yaml, got %s", getArgValue(args, "--rule-pack"))
				}
				if getArgValue(args, "--format") != "markdown" {
					t.Errorf("expected --format markdown, got %s", getArgValue(args, "--format"))
				}
				if getArgValue(args, "--redact") != "strict" {
					t.Errorf("expected --redact strict, got %s", getArgValue(args, "--redact"))
				}
				if getArgValue(args, "--fail-severity") != "medium" {
					t.Errorf("expected --fail-severity medium, got %s", getArgValue(args, "--fail-severity"))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Prepare paths inside temp directory
			mockBinDir := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(mockBinDir, 0755); err != nil {
				t.Fatal(err)
			}
			runnerTemp := filepath.Join(tmpDir, "temp-runner")
			if err := os.MkdirAll(runnerTemp, 0755); err != nil {
				t.Fatal(err)
			}
			ghOutput := filepath.Join(tmpDir, "gh-output")
			ghSummary := filepath.Join(tmpDir, "gh-summary")

			// Write empty output and summary files
			if err := os.WriteFile(ghOutput, []byte{}, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ghSummary, []byte{}, 0644); err != nil {
				t.Fatal(err)
			}

			// Path arg directory where mock scan will run
			scanDir := filepath.Join(tmpDir, "scan-target")
			if err := os.MkdirAll(scanDir, 0755); err != nil {
				t.Fatal(err)
			}

			// Create mock devdiag binary
			mockDevdiagPath := filepath.Join(mockBinDir, "devdiag")
			mockArgsLog := filepath.Join(tmpDir, "mock-args.log")
			mockScript := fmt.Sprintf(`#!/usr/bin/env bash
# Save arguments to log
echo "$@" > "%s"

# Mock saving report if --save-report is passed
for arg in "$@"; do
  if [ "$arg" = "--save-report" ]; then
    # The last argument is path
    PATH_ARG="${@: -1}"
    RUNS_DIR="${PATH_ARG}/.devdiag/runs/mockrun123"
    mkdir -p "${RUNS_DIR}"
    echo '{"RunID": "mockrun123", "Findings": []}' > "${RUNS_DIR}/report.json"
  fi
done

exit %s
`, mockArgsLog, tt.mockExitCode)

			if err := os.WriteFile(mockDevdiagPath, []byte(mockScript), 0755); err != nil {
				t.Fatal(err)
			}

			// Build command execution
			cmd := exec.Command(actionScript)
			cmd.Dir = tmpDir

			// Inherit environment and override GitHub Action variables
			cmd.Env = os.Environ()
			// Prepend mock bin to PATH
			pathEnv := os.Getenv("PATH")
			cmd.Env = append(cmd.Env, fmt.Sprintf("PATH=%s%c%s", mockBinDir, filepath.ListSeparator, pathEnv))
			cmd.Env = append(cmd.Env, fmt.Sprintf("RUNNER_TEMP=%s", runnerTemp))
			cmd.Env = append(cmd.Env, fmt.Sprintf("GITHUB_OUTPUT=%s", ghOutput))
			cmd.Env = append(cmd.Env, fmt.Sprintf("GITHUB_STEP_SUMMARY=%s", ghSummary))
			cmd.Env = append(cmd.Env, fmt.Sprintf("PATH_ARG=%s", scanDir))

			// Add test specific env variables
			for k, v := range tt.env {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}

			// Run action script
			outputBytes, err := cmd.CombinedOutput()
			stdout := string(outputBytes)
			exitCode := 0
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					exitCode = exitError.ExitCode()
				} else {
					t.Fatalf("failed to run command: %v", err)
				}
			}

			if exitCode != tt.wantExitCode {
				t.Errorf("got exit code %d, want %d. Output: %s", exitCode, tt.wantExitCode, stdout)
			}

			tt.verify(t, tmpDir, tt.env, stdout, "")
		})
	}
}

func readGHFile(t *testing.T, path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	res := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			res[parts[0]] = parts[1]
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return res
}

func readMockArgs(t *testing.T, tmpDir string) []string {
	logPath := filepath.Join(tmpDir, "mock-args.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	return fields
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func getArgValue(slice []string, argName string) string {
	for i, item := range slice {
		if item == argName && i+1 < len(slice) {
			return slice[i+1]
		}
	}
	return ""
}
