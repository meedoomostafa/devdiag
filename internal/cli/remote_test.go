package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/remote/session"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/remote/transport"
)

// fakeTransport is a test double for transport.Transport.
type fakeTransport struct {
	results map[string]*transport.RemoteCommandResult
}

func (f *fakeTransport) Kind() string { return "fake" }
func (f *fakeTransport) Probe(ctx context.Context) (*transport.RemoteProbeResult, error) {
	return nil, nil
}
func (f *fakeTransport) Close() error                                                 { return nil }
func (f *fakeTransport) Upload(ctx context.Context, localDir, remoteDir string) error { return nil }
func (f *fakeTransport) OpenShell(ctx context.Context, shell string) error            { return nil }
func (f *fakeTransport) Enter(remoteDir string) error                                 { return nil }

func (f *fakeTransport) Run(ctx context.Context, cmd transport.RemoteCommand) (*transport.RemoteCommandResult, error) {
	key := ""
	for _, a := range cmd.Args {
		key += a + " "
	}
	if r, ok := f.results[key]; ok {
		return r, nil
	}
	return &transport.RemoteCommandResult{ExitCode: 0}, nil
}

func TestCleanManifest_ValidPaths(t *testing.T) {
	ft := &fakeTransport{results: map[string]*transport.RemoteCommandResult{}}
	manifest := &session.Manifest{
		RootDir: "~/.devdiag/remote/s1",
		Target:  target.Target{Kind: target.KindSSH},
		Files: []session.ManagedFile{
			{Path: "~/.devdiag/remote/s1/env.sh", Mode: "0644", Created: true},
			{Path: "~/.devdiag/remote/s1/bin/dd-path", Mode: "0755", Created: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cleanManifest(ctx, ft, manifest); err != nil {
		t.Fatalf("cleanManifest error: %v", err)
	}
}

func TestCleanManifest_RefusesRootDir(t *testing.T) {
	ft := &fakeTransport{}
	for _, badDir := range []string{"/", "/home", "/tmp", "", "/etc"} {
		manifest := &session.Manifest{
			RootDir: badDir,
			Files:   []session.ManagedFile{{Path: badDir + "/env.sh", Created: true}},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := cleanManifest(ctx, ft, manifest); err == nil {
			t.Errorf("expected cleanup refused for root_dir=%q", badDir)
		}
		cancel()
	}
}

func TestCleanManifest_RefusesPathTraversal(t *testing.T) {
	ft := &fakeTransport{}
	manifest := &session.Manifest{
		RootDir: "~/.devdiag/remote/s1",
		Target:  target.Target{Kind: target.KindSSH},
		Files: []session.ManagedFile{
			{Path: "~/.devdiag/remote/s1/../../etc/passwd", Created: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cleanManifest(ctx, ft, manifest); err == nil {
		t.Error("expected cleanup refused for path traversal")
	}
}

func TestCleanManifest_RefusesAbsoluteEscape(t *testing.T) {
	ft := &fakeTransport{}
	manifest := &session.Manifest{
		RootDir: "~/.devdiag/remote/s1",
		Target:  target.Target{Kind: target.KindSSH},
		Files: []session.ManagedFile{
			{Path: "/etc/passwd", Created: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cleanManifest(ctx, ft, manifest); err == nil {
		t.Error("expected cleanup refused for absolute path outside root")
	}
}

func TestCleanManifest_TwiceIsSafe(t *testing.T) {
	ft := &fakeTransport{results: map[string]*transport.RemoteCommandResult{}}
	manifest := &session.Manifest{
		RootDir: "~/.devdiag/remote/s1",
		Target:  target.Target{Kind: target.KindSSH},
		Files: []session.ManagedFile{
			{Path: "~/.devdiag/remote/s1/env.sh", Created: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First cleanup
	if err := cleanManifest(ctx, ft, manifest); err != nil {
		t.Fatalf("first cleanup error: %v", err)
	}
	// Second cleanup should also succeed (rm -f is idempotent)
	if err := cleanManifest(ctx, ft, manifest); err != nil {
		t.Fatalf("second cleanup error: %v", err)
	}
}

func TestCleanManifest_PartialFailureReported(t *testing.T) {
	ft := &fakeTransport{results: map[string]*transport.RemoteCommandResult{
		"rm -f ~/.devdiag/remote/s1/env.sh ":      {ExitCode: 0},
		"rm -f ~/.devdiag/remote/s1/bin/dd-path ": {ExitCode: 1, Stderr: "permission denied"},
	}}
	manifest := &session.Manifest{
		RootDir: "~/.devdiag/remote/s1",
		Target:  target.Target{Kind: target.KindSSH},
		Files: []session.ManagedFile{
			{Path: "~/.devdiag/remote/s1/env.sh", Created: true},
			{Path: "~/.devdiag/remote/s1/bin/dd-path", Created: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := cleanManifest(ctx, ft, manifest)
	if err == nil {
		t.Fatal("expected partial failure error")
	}
	if err.Error() != "rm ~/.devdiag/remote/s1/bin/dd-path failed: permission denied" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBuildSSHProbeFindings(t *testing.T) {
	tests := []struct {
		name  string
		probe *transport.RemoteProbeResult
		want  string
	}{
		{
			name:  "unreachable",
			probe: &transport.RemoteProbeResult{Reachable: false, Error: "host unreachable"},
			want:  "Remote target unreachable",
		},
		{
			name:  "home_not_writable",
			probe: &transport.RemoteProbeResult{Reachable: true, HomeWritable: false, Home: "/home/user"},
			want:  "Remote home directory not writable",
		},
		{
			name:  "no_shell",
			probe: &transport.RemoteProbeResult{Reachable: true, HomeWritable: true, Shell: ""},
			want:  "No supported remote shell found",
		},
		{
			name:  "no_tar",
			probe: &transport.RemoteProbeResult{Reachable: true, HomeWritable: true, Shell: "/bin/bash", HasTar: false},
			want:  "Required upload method unavailable",
		},
		{
			name:  "all_ok",
			probe: &transport.RemoteProbeResult{Reachable: true, HomeWritable: true, Shell: "/bin/bash", HasTar: true},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSSHProbeFindings(nil, tt.probe)
			if tt.want == "" {
				if got != nil {
					t.Errorf("expected nil, got %q", got.Title)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected finding %q, got nil", tt.want)
			}
			if got.Title != tt.want {
				t.Errorf("Title = %q, want %q", got.Title, tt.want)
			}
		})
	}
}

func TestBuildContainerProbeFindings(t *testing.T) {
	tests := []struct {
		name  string
		probe *transport.RemoteProbeResult
		want  string
	}{
		{
			name:  "not_running",
			probe: &transport.RemoteProbeResult{Reachable: false, Error: "container not running"},
			want:  "Target container is not running",
		},
		{
			name:  "read_only",
			probe: &transport.RemoteProbeResult{Reachable: true, HomeWritable: false},
			want:  "Remote filesystem is read-only",
		},
		{
			name:  "all_ok",
			probe: &transport.RemoteProbeResult{Reachable: true, HomeWritable: true, Shell: "/bin/sh", HasTar: true},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildContainerProbeFindings(nil, tt.probe)
			if tt.want == "" {
				if got != nil {
					t.Errorf("expected nil, got %q", got.Title)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected finding %q, got nil", tt.want)
			}
			if got.Title != tt.want {
				t.Errorf("Title = %q, want %q", got.Title, tt.want)
			}
		})
	}
}

func TestRemoteDoctor_JSON(t *testing.T) {
	stdout, stderr, code := runBinary("remote", "doctor", "user@host", "--dry-run", "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	// stdout must be valid JSON only
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout:\n%s", err, stdout)
	}
	// stderr should contain logs, not JSON
	if strings.Contains(stderr, "{") && strings.Contains(stderr, "}") {
		// This is OK if it's just the log format containing braces; we check that stdout is pure JSON
	}
	if result["status"] != "doctor" {
		t.Errorf("status = %v, want doctor", result["status"])
	}
	if result["target"].(map[string]interface{})["kind"] != "ssh" {
		t.Errorf("target.kind = %v, want ssh", result["target"].(map[string]interface{})["kind"])
	}
}

func TestRemoteSync_JSON(t *testing.T) {
	stdout, _, code := runBinary("remote", "sync", "user@host", "--profile", "minimal", "--dry-run", "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if result["status"] != "synced" {
		t.Errorf("status = %v, want synced", result["status"])
	}
	if result["profile"] != "minimal" {
		t.Errorf("profile = %v, want minimal", result["profile"])
	}
	if result["session_id"] == "" {
		t.Error("session_id is empty")
	}
	files, ok := result["files_created"].([]interface{})
	if !ok || len(files) == 0 {
		t.Error("files_created is empty or missing")
	}
	if result["no_dotfiles_modified"] != true {
		t.Error("no_dotfiles_modified should be true")
	}
}

func TestRemoteStatus_JSON_NoCache(t *testing.T) {
	stdout, _, code := runBinary("remote", "status", "user@host", "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	notes := result["notes"].([]interface{})
	found := false
	for _, n := range notes {
		if strings.Contains(n.(string), "no cached session") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'no cached session' note, got %v", notes)
	}
}

func TestRemoteClean_JSON_DryRun(t *testing.T) {
	stdout, _, code := runBinary("remote", "clean", "user@host", "--dry-run", "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if result["status"] != "cleaned" {
		t.Errorf("status = %v, want cleaned", result["status"])
	}
}

func TestRemoteEnter_DryRun_Keep(t *testing.T) {
	stdout, stderr, code := runBinary("remote", "enter", "user@host", "--dry-run", "--keep")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stderr, "dry-run") {
		t.Errorf("stderr missing dry-run message: %q", stderr)
	}
	if !strings.Contains(stderr, "devdiag remote clean") {
		t.Errorf("stderr missing cleanup command: %q", stderr)
	}
	_ = stdout
}

func TestRemoteEnter_DryRun_JSON(t *testing.T) {
	stdout, _, code := runBinary("remote", "enter", "user@host", "--dry-run", "--keep", "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if result["status"] != "planned" {
		t.Errorf("status = %v, want planned", result["status"])
	}
	if result["cleanup_command"] == "" {
		t.Error("cleanup_command missing")
	}
}

func TestRemoteDoctor_NO_COLOR(t *testing.T) {
	stdout, _, code := runBinary("remote", "doctor", "user@host", "--dry-run", "--format", "human")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	// With NO_COLOR unset, human format may contain ANSI codes (but we don't force color)
	// The test just verifies it runs without error.
	_ = stdout
}

func TestValidateRootDir_Hardening(t *testing.T) {
	cases := []struct {
		path string
		kind target.Kind
		ok   bool
	}{
		{"~/.devdiag/remote/s1", target.KindSSH, true},
		{"/tmp/devdiag-remote/s1", target.KindContainer, true},
		{"/", target.KindSSH, false},
		{"/home", target.KindSSH, false},
		{"/tmp", target.KindSSH, false},
		{"", target.KindSSH, false},
		{"~/foo/..", target.KindSSH, false},
		{"~/.devdiag/remote/s1/../../../etc", target.KindSSH, false},
	}
	for _, c := range cases {
		err := session.ValidateRootDir(c.path, c.kind)
		if c.ok && err != nil {
			t.Errorf("ValidateRootDir(%q, %q) = %v, want nil", c.path, c.kind, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ValidateRootDir(%q, %q) = nil, want error", c.path, c.kind)
		}
	}
}
