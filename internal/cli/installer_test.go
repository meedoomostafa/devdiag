package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runInstallerWithEnv(t *testing.T, env map[string]string, args ...string) (string, string, error) {
	t.Helper()
	cmdArgs := append([]string{"../../scripts/install.sh"}, args...)
	cmd := exec.Command("bash", cmdArgs...)

	cmdEnv := os.Environ()
	for k, v := range env {
		for i := 0; i < len(cmdEnv); i++ {
			if strings.HasPrefix(cmdEnv[i], k+"=") {
				cmdEnv = append(cmdEnv[:i], cmdEnv[i+1:]...)
				i--
			}
		}
		cmdEnv = append(cmdEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = cmdEnv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runShellFunctionTest(t *testing.T, testBody string) string {
	scriptData, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatalf("failed to read install.sh: %v", err)
	}

	var runnerScript strings.Builder
	runnerScript.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n")

	scriptLines := strings.Split(string(scriptData), "\n")
	// Extract up to the OS_NAME check (everything before main script body execution)
	for i := 0; i < len(scriptLines); i++ {
		if strings.HasPrefix(scriptLines[i], "OS_NAME=") {
			break
		}
		runnerScript.WriteString(scriptLines[i])
		runnerScript.WriteString("\n")
	}

	runnerScript.WriteString("\n")
	runnerScript.WriteString(testBody)

	tmpFile := filepath.Join(t.TempDir(), "test_runner.sh")
	if err := os.WriteFile(tmpFile, []byte(runnerScript.String()), 0o755); err != nil {
		t.Fatalf("failed to write test runner: %v", err)
	}

	cmd := exec.Command("bash", tmpFile)
	// The sourced prelude includes the top-level "latest" resolution block;
	// pin a version so shell-function tests never hit the live GitHub API
	// (403 rate limits on shared runners made this flake).
	cmd.Env = append(os.Environ(), "DEVDIAG_INSTALL_VERSION=v0.0.0-test")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("shell test failed: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func TestInstaller_ConflictingFlagsExits2(t *testing.T) {
	_, stderr, err := runInstallerWithEnv(t, nil, "--add-to-path", "--no-add-to-path")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2, got %d. stderr: %s", exitErr.ExitCode(), stderr)
		}
	} else {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if !strings.Contains(stderr, "cannot specify both --add-to-path and --no-add-to-path") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

func TestInstaller_DryRunNoFilesCreated(t *testing.T) {
	tempHome := t.TempDir()
	env := map[string]string{
		"HOME":                    tempHome,
		"DEVDIAG_INSTALL_VERSION": "v0.2.4",
	}
	stdout, stderr, err := runInstallerWithEnv(t, env, "--dry-run")
	if err != nil {
		t.Fatalf("unexpected error: %v, stderr: %s", err, stderr)
	}

	metadataPath := filepath.Join(tempHome, ".config", "devdiag")
	if _, err := os.Stat(metadataPath); err == nil || !os.IsNotExist(err) {
		t.Fatalf("dry-run created metadata directory: %s", metadataPath)
	}

	expectedFields := []string{
		"repo=meedoomostafa/devdiag",
		"requested_version=v0.2.4",
		"resolved_version=0.2.4",
		"app_version=0.2.4",
		"archive=https://github.com/meedoomostafa/devdiag/archive/refs/tags/v0.2.4.tar.gz",
		"bin_dir=",
		"install_path=",
		"metadata_path=",
		"go=",
		"checksum=none",
		"path_status=",
		"would_add_to_path=false",
		"shell_target=auto",
	}
	for _, f := range expectedFields {
		if !strings.Contains(stdout, f) {
			t.Errorf("dry-run output missing expected field %q: %s", f, stdout)
		}
	}
}

func TestInstaller_ResolveLatestMocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/meedoomostafa/devdiag/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v0.2.7"}`)
	}))
	defer ts.Close()

	env := map[string]string{
		"DEVDIAG_GITHUB_API_BASE_URL": ts.URL,
		"DEVDIAG_INSTALL_VERSION":     "latest",
	}
	stdout, stderr, err := runInstallerWithEnv(t, env, "--dry-run")
	if err != nil {
		t.Fatalf("unexpected error: %v, stderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "resolved_version=0.2.7") {
		t.Fatalf("expected resolved version 0.2.7, got output: %s", stdout)
	}
}

func TestInstaller_VersionNormalization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"v0.2.4", "resolved_version=0.2.4"},
		{"refs/tags/v0.2.4", "resolved_version=0.2.4"},
		{"main", "resolved_version=main"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			env := map[string]string{
				"DEVDIAG_INSTALL_VERSION": tc.input,
			}
			stdout, _, err := runInstallerWithEnv(t, env, "--dry-run")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(stdout, tc.expected) {
				t.Errorf("expected %q in output, got: %s", tc.expected, stdout)
			}
		})
	}
}

func TestInstaller_ShellProfileIdempotency(t *testing.T) {
	testBody := `
temp_home="$(mktemp -d)"
trap 'rm -rf "${temp_home}"' EXIT
bashrc="${temp_home}/.bashrc"
fish_config="${temp_home}/config.fish"

# 1. Update sh profile first time
update_sh_profile "${bashrc}" "/mock/path/one"
if ! grep -q "/mock/path/one" "${bashrc}"; then
    echo "Error: path one not found in bashrc"
    exit 1
fi

# 2. Update sh profile second time with same path (should be idempotent)
update_sh_profile "${bashrc}" "/mock/path/one"
count=$(grep -c "# >>> devdiag PATH >>>" "${bashrc}")
if [[ "${count}" -ne 1 ]]; then
    echo "Error: block duplicated in bashrc (count=${count})"
    exit 1
fi

# 3. Update sh profile with different path (should replace the block)
update_sh_profile "${bashrc}" "/mock/path/two"
if grep -q "/mock/path/one" "${bashrc}"; then
    echo "Error: old path one still present in bashrc"
    exit 1
fi
if ! grep -q "/mock/path/two" "${bashrc}"; then
    echo "Error: new path two not found in bashrc"
    exit 1
fi
count=$(grep -c "# >>> devdiag PATH >>>" "${bashrc}")
if [[ "${count}" -ne 1 ]]; then
    echo "Error: block count not 1 after replacement (count=${count})"
    exit 1
fi

# 4. Same checks for fish profile
update_fish_profile "${fish_config}" "/mock/path/one"
if ! grep -q "/mock/path/one" "${fish_config}"; then
    echo "Error: path one not found in fish_config"
    exit 1
fi

update_fish_profile "${fish_config}" "/mock/path/one"
count=$(grep -c "# >>> devdiag PATH >>>" "${fish_config}")
if [[ "${count}" -ne 1 ]]; then
    echo "Error: block duplicated in fish_config (count=${count})"
    exit 1
fi

update_fish_profile "${fish_config}" "/mock/path/two"
if grep -q "/mock/path/one" "${fish_config}"; then
    echo "Error: old path one still present in fish_config"
    exit 1
fi
if ! grep -q "/mock/path/two" "${fish_config}"; then
    echo "Error: new path two not found in fish_config"
    exit 1
fi
echo "OK"
`
	out := runShellFunctionTest(t, testBody)
	if !strings.Contains(out, "OK") {
		t.Fatalf("shell test failed to print OK: %s", out)
	}
}

func runUpdateCmd(env []string, args ...string) (string, string, int) {
	cmd := exec.Command(binaryPath, append([]string{"update"}, args...)...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()
	return stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()
}

func TestUpdate_MetadataMissing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v0.2.7"}`)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)

	stdout, stderr, code := runUpdateCmd(env, "--dry-run")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "action: metadata_missing") {
		t.Errorf("expected metadata_missing, got: %s", stdout)
	}
}

func TestUpdate_MetadataMalformed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v0.2.7"}`)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte("invalid-json"), 0o644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)

	stdout, stderr, code := runUpdateCmd(env, "--dry-run")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "action: metadata_malformed") {
		t.Errorf("expected metadata_malformed, got: %s", stdout)
	}
}

func TestUpdate_AlreadyLatest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v0.2.7"}`)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	metadataContent := `{
		"schema_version": "1",
		"repo": "meedoomostafa/devdiag",
		"source_ref": "v0.2.7",
		"resolved_version": "0.2.7",
		"install_dir": "/mock/bin",
		"binary_path": "/mock/bin/devdiag",
		"install_method": "source-archive"
	}`
	if err := os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte(metadataContent), 0o644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)

	stdout, stderr, code := runUpdateCmd(env, "--dry-run")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "action: already_up_to_date") {
		t.Errorf("expected already_up_to_date, got: %s", stdout)
	}
}

func TestUpdate_CurrentNewerThanLatestDoesNotDowngrade(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v0.2.5"}`)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	metadataContent := `{
		"schema_version": "1",
		"repo": "meedoomostafa/devdiag",
		"source_ref": "v0.2.7",
		"resolved_version": "0.2.7",
		"install_dir": "/mock/bin",
		"binary_path": "/mock/bin/devdiag",
		"install_method": "source-archive"
	}`
	if err := os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte(metadataContent), 0o644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)

	stdout, stderr, code := runUpdateCmd(env, "--dry-run")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "action: already_up_to_date") {
		t.Errorf("expected already_up_to_date, got: %s", stdout)
	}
}

func TestUpdate_UpdateAvailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v0.3.1"}`)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	metadataContent := `{
		"schema_version": "1",
		"repo": "meedoomostafa/devdiag",
		"source_ref": "v0.2.4",
		"resolved_version": "0.2.4",
		"install_dir": "/mock/bin",
		"binary_path": "/mock/bin/devdiag",
		"install_method": "source-archive"
	}`
	if err := os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte(metadataContent), 0o644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)

	stdout, stderr, code := runUpdateCmd(env, "--dry-run")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "action: update_available") {
		t.Errorf("expected update_available, got: %s", stdout)
	}
}

func TestUpdate_APIFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)

	_, stderr, code := runUpdateCmd(env, "--dry-run")
	if code == 0 {
		t.Fatal("expected non-zero exit code on API failure")
	}

	if !strings.Contains(stderr, "failed to resolve latest DevDiag release") {
		t.Errorf("unexpected stderr: %s", stderr)
	}
}

func TestUpdate_TokenProtected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	tempHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
		"GITHUB_TOKEN=SECRET_MY_TOKEN_VAL",
	)

	_, stderr, code := runUpdateCmd(env, "--dry-run")
	if code == 0 {
		t.Fatal("expected non-zero exit code on unauthorized")
	}

	if strings.Contains(stderr, "SECRET_MY_TOKEN_VAL") {
		t.Errorf("token leaked in stderr: %s", stderr)
	}
}

func TestUpdate_AppliesVerifiedBinaryUpdate(t *testing.T) {
	tempHome := t.TempDir()
	binDir := filepath.Join(tempHome, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(binDir, "devdiag")
	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\necho old\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	metadataContent := fmt.Sprintf(`{
		"schema_version": "1",
		"repo": "meedoomostafa/devdiag",
		"source_ref": "v0.2.4",
		"resolved_version": "0.2.4",
		"install_dir": %q,
		"binary_path": %q,
		"install_method": "source-archive"
	}`, binDir, targetPath)
	if err := os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte(metadataContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Release archive with a new binary; served alongside checksums.txt.
	assetName := fmt.Sprintf("devdiag_9.9.9_linux_%s.tar.gz", runtime.GOARCH)
	var archiveBuf bytes.Buffer
	gz := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gz)
	newBinary := []byte("#!/bin/sh\necho updated-9.9.9\n")
	tw.WriteHeader(&tar.Header{Name: "devdiag", Mode: 0o755, Size: int64(len(newBinary)), Typeflag: tar.TypeReg})
	tw.Write(newBinary)
	tw.Close()
	gz.Close()
	archive := archiveBuf.Bytes()
	sum := sha256.Sum256(archive)
	checksums := hex.EncodeToString(sum[:]) + "  " + assetName + "\n"

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/meedoomostafa/devdiag/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[{"name":%q,"browser_download_url":"%s/dl/%s"},{"name":"checksums.txt","browser_download_url":"%s/dl/checksums.txt"}]}`, assetName, ts.URL, assetName, ts.URL)
		case r.URL.Path == "/dl/"+assetName:
			w.Write(archive)
		case r.URL.Path == "/dl/checksums.txt":
			fmt.Fprint(w, checksums)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Fake gh CLI that always verifies.
	ghDir := t.TempDir()
	ghPath := filepath.Join(ghDir, "gh")
	if err := os.WriteFile(ghPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
		"DEVDIAG_GH_PATH="+ghPath,
	)

	stdout, stderr, code := runUpdateCmd(env)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stdout: %s stderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"action: applying_update", "step: verifying checksum", "step: verifying provenance attestation", "action: updated"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q: %s", want, stdout)
		}
	}
	updated, err := os.ReadFile(targetPath)
	if err != nil || !strings.Contains(string(updated), "updated-9.9.9") {
		t.Fatalf("binary not updated: %q err=%v", updated, err)
	}
	backup, err := os.ReadFile(targetPath + ".old")
	if err != nil || !strings.Contains(string(backup), "echo old") {
		t.Fatalf("backup missing: %q err=%v", backup, err)
	}
	meta, err := os.ReadFile(filepath.Join(metadataDir, "install.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"install_method": "release-binary"`, `"resolved_version": "9.9.9"`, `"checksum_provided": true`} {
		if !strings.Contains(string(meta), want) {
			t.Fatalf("metadata missing %q: %s", want, meta)
		}
	}
}

func TestUpdate_RefusesWhenAttestationFails(t *testing.T) {
	tempHome := t.TempDir()
	binDir := filepath.Join(tempHome, "bin")
	os.MkdirAll(binDir, 0o755)
	targetPath := filepath.Join(binDir, "devdiag")
	os.WriteFile(targetPath, []byte("old"), 0o755)
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	os.MkdirAll(metadataDir, 0o755)
	os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte(fmt.Sprintf(`{"schema_version":"1","repo":"meedoomostafa/devdiag","resolved_version":"0.2.4","install_dir":%q,"binary_path":%q}`, binDir, targetPath)), 0o644)

	assetName := fmt.Sprintf("devdiag_9.9.9_linux_%s.tar.gz", runtime.GOARCH)
	var archiveBuf bytes.Buffer
	gz := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gz)
	body := []byte("bin")
	tw.WriteHeader(&tar.Header{Name: "devdiag", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	gz.Close()
	archive := archiveBuf.Bytes()
	sum := sha256.Sum256(archive)

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/meedoomostafa/devdiag/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[{"name":%q,"browser_download_url":"%s/dl/a"},{"name":"checksums.txt","browser_download_url":"%s/dl/c"}]}`, assetName, ts.URL, ts.URL)
		case r.URL.Path == "/dl/a":
			w.Write(archive)
		case r.URL.Path == "/dl/c":
			fmt.Fprint(w, hex.EncodeToString(sum[:])+"  "+assetName+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ghPath := filepath.Join(t.TempDir(), "gh")
	os.WriteFile(ghPath, []byte("#!/bin/sh\nexit 1\n"), 0o755)

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
		"DEVDIAG_GH_PATH="+ghPath,
	)
	stdout, stderr, code := runUpdateCmd(env)
	if code == 0 {
		t.Fatalf("expected refusal, got success. stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "attestation") && !strings.Contains(stdout, "attestation") {
		t.Fatalf("refusal should mention attestation. stdout: %s stderr: %s", stdout, stderr)
	}
	if data, _ := os.ReadFile(targetPath); string(data) != "old" {
		t.Fatalf("binary must be untouched on refusal, got %q", data)
	}
}

func TestUpdate_RefusesAssetlessRelease(t *testing.T) {
	tempHome := t.TempDir()
	binDir := filepath.Join(tempHome, "bin")
	os.MkdirAll(binDir, 0o755)
	targetPath := filepath.Join(binDir, "devdiag")
	os.WriteFile(targetPath, []byte("old"), 0o755)
	metadataDir := filepath.Join(tempHome, ".config", "devdiag")
	os.MkdirAll(metadataDir, 0o755)
	os.WriteFile(filepath.Join(metadataDir, "install.json"), []byte(fmt.Sprintf(`{"schema_version":"1","repo":"meedoomostafa/devdiag","resolved_version":"0.2.4","install_dir":%q,"binary_path":%q}`, binDir, targetPath)), 0o644)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"tag_name":"v0.4.0","assets":[]}`)
	}))
	defer ts.Close()

	env := append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+tempHome+"/.config",
		"DEVDIAG_GITHUB_API_BASE_URL="+ts.URL,
	)
	stdout, stderr, code := runUpdateCmd(env)
	if code == 0 {
		t.Fatalf("expected refusal for asset-less release, got success: %s", stdout)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "install.sh") {
		t.Fatalf("refusal should point at install.sh: %s", combined)
	}
	if data, _ := os.ReadFile(targetPath); string(data) != "old" {
		t.Fatalf("binary must be untouched, got %q", data)
	}
}

func TestUpdate_InvalidFlagsExits2(t *testing.T) {
	_, stderr, code := runUpdateCmd(nil, "--invalid-flag")
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d. stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "unknown flag") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}
